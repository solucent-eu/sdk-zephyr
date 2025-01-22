/*
 * Copyright (c) 2020 InnBlue
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(tftp_client, CONFIG_TFTP_LOG_LEVEL);

#include <stddef.h>
#include <zephyr/net/tftp.h>
#include "tftp_client.h"

#define ADDRLEN(sa) \
	(sa.sa_family == AF_INET ? \
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

static int error_callback(struct tftpc *client, int block_no);

/*
 * Prepare a request as required by RFC1350. This packet can be sent
 * out directly to the TFTP server.
 */
static size_t make_request(uint8_t *buf, int request,
			   const char *remote_file, const char *mode,
				 uint16_t max_blksize)
{
	char *ptr = (char *)buf;
	const char def_mode[] = "octet";

	// a limitation that makes code simpler below
	if (TFTP_BLOCK_SIZE < 50)
		return 0;

	/* Fill in the Request Type. */
	sys_put_be16(request, ptr);
	ptr += 2;

	/* Copy the name of the remote file. */
	strncpy(ptr, remote_file, TFTP_BLOCK_SIZE-30);
	ptr += strlen(remote_file);
	*ptr++ = '\0';

	/* Default to "Octet" if mode not specified. */
	if (mode == NULL) {
		mode = def_mode;
	}

	/* Copy the mode of operation. */
	strncpy(ptr, mode, TFTP_MAX_MODE_SIZE);
	ptr += strlen(mode);
	*ptr++ = '\0';

	// Implement RFC2348
	if (max_blksize != 512) {
		strcpy(ptr, "blksize");
		ptr += strlen(ptr);
		*ptr++ = '\0';

		sprintf(ptr, "%d", max_blksize);
		ptr += strlen(ptr);
		*ptr++ = '\0';
	}

	return ptr - (char *)buf;
}

/*
 * Send Data message to the TFTP Server and receive ACK message from it.
 */
static int send_data(int sock, struct tftpc *client, size_t data_size)
{
	int ret;
	int send_count = 0, ack_count = 0;
	struct zsock_pollfd fds = {
		.fd     = sock,
		.events = ZSOCK_POLLIN,
	};

	LOG_DBG("Client send data: block no %u, size %u", client->tftpc_block_no, data_size + TFTP_HEADER_SIZE);

	do {
		if (send_count > TFTP_REQ_RETX) {
			LOG_ERR("No more retransmits. Exiting");
			return TFTPC_RETRIES_EXHAUSTED;
		}

		/* Prepare DATA packet, send it out then poll for ACK response */
		sys_put_be16(DATA_OPCODE, client->tftp_buf);
		sys_put_be16(client->tftpc_block_no, client->tftp_buf + 2);

		ret = zsock_send(sock, client->tftp_buf, data_size + TFTP_HEADER_SIZE, 0);
		if (ret < 0) {
			LOG_ERR("send() error: %d", -errno);
			return -errno;
		}

		do {
			if (ack_count > TFTP_REQ_RETX) {
				LOG_WRN("No more waiting for ACK");
				break;
			}

			ret = zsock_poll(&fds, 1, CONFIG_TFTPC_REQUEST_TIMEOUT);
			if (ret < 0) {
				LOG_ERR("recv() error: %d", -errno);
				return -errno;  /* IO error */
			} else if (ret == 0) {
				break;		/* no response, re-send data */
			}

			ret = zsock_recv(sock, client->tftp_buf, TFTPC_MAX_BUF_SIZE, 0);
			if (ret < 0) {
				LOG_ERR("recv() error: %d", -errno);
				return -errno;
			}

			if (ret != TFTP_HEADER_SIZE) {
				break; /* wrong response, re-send data */
			}

			uint16_t opcode = sys_get_be16(client->tftp_buf);
			uint16_t block_no = sys_get_be16(client->tftp_buf + 2);

			LOG_DBG("Receive: opcode %u, block no %u, size %d",
				opcode, block_no, ret);

			if (opcode == ACK_OPCODE && block_no == client->tftpc_block_no) {
				return TFTPC_SUCCESS;
			} else if (opcode == ACK_OPCODE && block_no < client->tftpc_block_no) {
				LOG_WRN("Server responded with obsolete block number.");
				ack_count++;
				continue; /* duplicated ACK */
			} else if (opcode == ERROR_OPCODE) {
				error_callback(client, block_no);
				LOG_WRN("Server responded with obsolete block number.");
				break;
			} else {
				LOG_ERR("Server responded with invalid opcode or block number.");
				break; /* wrong response, re-send data */
			}
		} while (true);

		send_count++;
	} while (true);

	return TFTPC_REMOTE_ERROR;
}

/*
 * Send an Error Message to the TFTP Server.
 */
static inline int send_err(int sock, struct tftpc *client, int err_code, char *err_msg)
{
	uint32_t req_size;

	LOG_DBG("Client sending error code: %d", err_code);

	/* Fill in the "Err" Opcode and the actual error code. */
	sys_put_be16(ERROR_OPCODE, client->tftp_buf);
	sys_put_be16(err_code, client->tftp_buf + 2);
	req_size = 4;

	/* Copy the Error String. */
	if (err_msg != NULL) {
		size_t copy_len = strlen(err_msg);

		if (copy_len > sizeof(client->tftp_buf) - req_size) {
			copy_len = sizeof(client->tftp_buf) - req_size;
		}

		memcpy(client->tftp_buf + req_size, err_msg, copy_len);
		req_size += copy_len;
	}

	/* Send Error to server. */
	return zsock_send(sock, client->tftp_buf, req_size, 0);
}

/*
 * Send an Ack Message to the TFTP Server.
 */
static inline int send_ack(int sock, struct tftphdr_ack *ackhdr)
{
	LOG_DBG("Client acking block number: %d", ntohs(ackhdr->block));

	return zsock_send(sock, ackhdr, sizeof(struct tftphdr_ack), 0);
}

static int send_request(int sock, struct tftpc *client,
			int request, const char *remote_file, const char *mode,
			unsigned int max_blksize)
{
	int tx_count = 0;
	size_t req_size;
	int ret;

	/* Create TFTP Request. */
	req_size = make_request(client->tftp_buf, request, remote_file, mode, max_blksize);

	do {
		tx_count++;

		LOG_DBG("Sending TFTP request %d file %s", request,
			remote_file);

		/* Send the request to the server */
		ret = zsock_sendto(sock, client->tftp_buf, req_size, 0, &client->server,
				   ADDRLEN(client->server));
		if (ret < 0) {
			break;
		}

		/* Poll for the response */
		struct zsock_pollfd fds = {
			.fd     = sock,
			.events = ZSOCK_POLLIN,
		};

		ret = zsock_poll(&fds, 1, CONFIG_TFTPC_REQUEST_TIMEOUT);
		if (ret <= 0) {
			LOG_DBG("Failed to get data from the TFTP Server"
				", req. no. %d", tx_count);
			continue;
		}

		/* Receive data from the TFTP Server. */
		struct sockaddr from_addr;
		socklen_t from_addr_len = sizeof(from_addr);

		ret = zsock_recvfrom(sock, client->tftp_buf, TFTPC_MAX_BUF_SIZE, 0,
				     &from_addr, &from_addr_len);
		if (ret < TFTP_HEADER_SIZE) {
			req_size = make_request(client->tftp_buf, request,
						remote_file, mode, max_blksize);
			continue;
		}

  	// Implement RFC2348
		uint16_t opcode = sys_get_be16(client->tftp_buf);
		client->blksize = 512;
		if (opcode == OACK_OPCODE) {
			if (ret < 2 + 8 + 2) {
				LOG_ERR("Invalid OACK packet size %d", ret);
				ret = -EIO;
				break;
			}
			// parse MTU
			char *ptr = (char *)client->tftp_buf + 2;
			if (strncmp(ptr, "blksize", 7) == 0) {
				ptr += 8;
				client->blksize = atoi(ptr);
				if (client->blksize < 8 || client->blksize > TFTP_BLOCK_SIZE) {
					send_err(sock, client, TFTP_ERROR_OPTION, "invalid blksize");
					LOG_ERR("Invalid block size %d", client->blksize);
					ret = -EINVAL;
					break;
				}
			}
			if (request == READ_REQUEST) {
				// we need to respond with ACK
				struct tftphdr_ack ackhdr = {
					.opcode = htons(ACK_OPCODE),
					.block = htons(0)
				};
				ret = zsock_sendto(sock, &ackhdr, sizeof(ackhdr), 0, &from_addr,
						from_addr_len);
				if (ret < 0)
					break;

				ret = zsock_poll(&fds, 1, CONFIG_TFTPC_REQUEST_TIMEOUT);
				if (ret <= 0) {
					ret = -EIO;
					break;
				}

				ret = zsock_recvfrom(sock, client->tftp_buf, TFTPC_MAX_BUF_SIZE, 0,
								&from_addr, &from_addr_len);
				if (ret < TFTP_HEADER_SIZE) {
					ret = -EIO;
					break;
				}
			} else if (request == WRITE_REQUEST) {
				// remove OACK, simulate normal ACK
				sys_put_be16(ACK_OPCODE, client->tftp_buf);
				sys_put_be16(0, client->tftp_buf + 2);
				ret = 4;
			}
		}

		/* Limit communication to the specific address:port */
		if (zsock_connect(sock, &from_addr, from_addr_len) < 0) {
			ret = -errno;
			LOG_ERR("connect failed, err %d", ret);
			break;
		}

		break;

	} while (tx_count <= TFTP_REQ_RETX);

	return ret;
}

static int file_callback(struct tftpc *client, enum tftp_evt_type et, const char *open_param)
{
	if (client->callback) {
		struct tftp_evt evt = {
			.type = et
		};

		if (open_param)
			strncpy(client->tftp_buf, open_param, sizeof(client->tftp_buf));
		else
			client->tftp_buf[0] = '\0';
		evt.param.data.data_ptr = NULL;
		evt.param.data.len      = 0;
		return client->callback(&evt);
	}

	return 0;
}

static int data_callback(struct tftpc *client, enum tftp_evt_type et, char *data, uint16_t data_size)
{
	if (client->callback) {
		struct tftp_evt evt = {
			.type = et
		};

		evt.param.data.data_ptr = data;
		evt.param.data.len      = data_size;
		return client->callback(&evt);
	}

	return 0;
}

static int error_callback(struct tftpc *client, int block_no)
{
	if (client->callback) {
		struct tftp_evt evt = {
			.type = TFTP_EVT_ERROR
		};

		evt.param.error.msg = client->tftp_buf + TFTP_HEADER_SIZE;
		evt.param.error.code = block_no;
		client->callback(&evt);
	}

	return 0;
}

int tftp_get(struct tftpc *client, const char *remote_file,
				const char *open_param, const char *mode,
				unsigned int max_blksize)
{
	int sock;
	int tx_count = 0;
	struct tftphdr_ack ackhdr = {
		.opcode = htons(ACK_OPCODE),
		.block = htons(1)
	};
	int rcv_size;
	int ret;

	if (client == NULL || remote_file == NULL || (open_param && !open_param[0])) {
		return -EINVAL;
	}

	sock = zsock_socket(client->server.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket: %d", errno);
		return -errno;
	}

	client->tftpc_block_no = 1;
	client->tftpc_index = 0;
	if (open_param) {
		ret = file_callback(client, TFTP_EVT_GETDATA, open_param);
		if (ret < 0) {
			zsock_close(sock);
			return ret;
		}
	}

	/* Send out the READ request to the TFTP Server. */
	ret = send_request(sock, client, READ_REQUEST, remote_file, mode, max_blksize);
	rcv_size = ret;

	while (rcv_size >= TFTP_HEADER_SIZE && rcv_size <= TFTPC_MAX_BUF_SIZE) { //? TFTP_HEADER_SIZE+client->blksize
		/* Process server response. */
		uint16_t opcode = sys_get_be16(client->tftp_buf);
		uint16_t block_no = sys_get_be16(client->tftp_buf + 2);

		LOG_DBG("Received data: opcode %u, block no %u, size %d",
			opcode, block_no, rcv_size);

		if (opcode == ERROR_OPCODE) {
			error_callback(client, block_no);
			ret = TFTPC_REMOTE_ERROR;
			break;
		} else if (opcode != DATA_OPCODE) {
			LOG_ERR("Server responded with invalid opcode.");
			ret = TFTPC_REMOTE_ERROR;
			break;
		}

		if (block_no == client->tftpc_block_no) {
			uint32_t data_size = rcv_size - TFTP_HEADER_SIZE;

			client->tftpc_block_no++;
			ackhdr.block = htons(block_no);
			tx_count = 0;

			/* Send received data to client */
			ret = data_callback(client, TFTP_EVT_GETDATA, client->tftp_buf + TFTP_HEADER_SIZE, data_size);
			if (ret < 0) {
				LOG_ERR("Failed to process received data.");
				if (send_err(sock, client, TFTP_ERROR_DISK_FULL, NULL) < 0) {
					LOG_ERR("Failed to send error response, err: %d",
						-errno);
				}
				ret = TFTPC_BUFFER_OVERFLOW;
				goto get_end;
			}

			/* Update the index. */
			client->tftpc_index += data_size;

			/* Per RFC1350, the end of a transfer is marked
			 * by datagram size < client->blksize.
			 */
			if (rcv_size < client->blksize) {
				(void)send_ack(sock, &ackhdr);
				ret = client->tftpc_index;
				LOG_DBG("%d bytes received.", ret);
				/* RFC1350: The host acknowledging the final DATA packet may
				 * terminate its side of the connection on sending the final ACK.
				 */
				break;
			}
		}

		/* Poll for the response */
		struct zsock_pollfd fds = {
			.fd     = sock,
			.events = ZSOCK_POLLIN,
		};

		do {
			if (tx_count > TFTP_REQ_RETX) {
				LOG_ERR("No more retransmits. Exiting");
				ret = TFTPC_RETRIES_EXHAUSTED;
				goto get_end;
			}

			/* Send ACK to the TFTP Server */
			(void)send_ack(sock, &ackhdr);
			tx_count++;
		} while (zsock_poll(&fds, 1, CONFIG_TFTPC_REQUEST_TIMEOUT) <= 0);

		/* Receive data from the TFTP Server. */
		ret = zsock_recv(sock, client->tftp_buf, TFTPC_MAX_BUF_SIZE, 0);
		rcv_size = ret;
	}

	if (!(rcv_size >= TFTP_HEADER_SIZE && rcv_size <= TFTPC_MAX_BUF_SIZE)) { //? TFTP_HEADER_SIZE+client->blksize
		ret = TFTPC_REMOTE_ERROR;
	}

get_end:
	zsock_close(sock);
	file_callback(client, TFTP_EVT_GETDATA, NULL);
	return ret;
}

int tftp_put(struct tftpc *client, const char *remote_file,
			const char *open_param, const char *mode, unsigned int max_blksize)
{
	int sock;
	int ret;

	if (client == NULL || remote_file == NULL || (open_param && !open_param[0])) {
		return -EINVAL;
	}

	sock = zsock_socket(client->server.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket: %d", errno);
		return -errno;
	}

	client->tftpc_block_no = 1;
	client->tftpc_index = 0;
	if (open_param) {
		ret = file_callback(client, TFTP_EVT_PUTDATA, open_param);
		if (ret < 0) {
			zsock_close(sock);
			return ret;
		}
	}

	/* Send out the WRITE request to the TFTP Server. */
	ret = send_request(sock, client, WRITE_REQUEST, remote_file, mode, max_blksize);

	/* Check connection initiation result */
	if (ret >= TFTP_HEADER_SIZE) {
		uint16_t opcode = sys_get_be16(client->tftp_buf);
		uint16_t block_no = sys_get_be16(client->tftp_buf + 2);

		LOG_DBG("Receive: opcode %u, block no %u, size %d", opcode, block_no, ret);

		if (opcode == ERROR_OPCODE) {
			error_callback(client, block_no);
			LOG_ERR("Server responded with service reject.");
			ret = TFTPC_REMOTE_ERROR;
			goto put_end;
		} else if (opcode != ACK_OPCODE || block_no != 0) {
			LOG_ERR("Server responded with invalid opcode or block number.");
			ret = TFTPC_REMOTE_ERROR;
			goto put_end;
		}
	} else {
		ret = TFTPC_REMOTE_ERROR;
		goto put_end;
	}

	/* Send out data by chunks */
	do {
		ret = data_callback(client, TFTP_EVT_PUTDATA, client->tftp_buf + TFTP_HEADER_SIZE, client->blksize);
		if (ret < 0) {
			LOG_ERR("Failed to process sent data.");
			if (send_err(sock, client, TFTP_ERROR_ILLEGAL_OP, NULL) < 0) {
				LOG_ERR("Failed to send error response, err: %d",
					-errno);
			}
			ret = TFTPC_BUFFER_OVERFLOW;
			goto put_end;
		}
		int send_size = ret;

		/* Send. */
		ret = send_data(sock, client, send_size);
		if (ret != TFTPC_SUCCESS) {
			goto put_end;
		} else {
			client->tftpc_index += send_size;
			client->tftpc_block_no++;
		}

		/* Per RFC1350, the end of a transfer is marked
		 * by datagram size < client->blksize.
		 */
		if (send_size < client->blksize) {
			ret = client->tftpc_index;
			LOG_DBG("%d bytes sent.", ret);
			break;
		}
	} while (true);

put_end:
	zsock_close(sock);
	file_callback(client, TFTP_EVT_PUTDATA, NULL);
	return ret;
}
