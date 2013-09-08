/*
 * Copyright (C) 2012 B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <ctype.h>
#include <jansson.h>
#include "alfred.h"

int alfred_client_request_data(struct globals *globals)
{
	unsigned char buf[MAX_PAYLOAD], *pos;
	struct alfred_request_v0 *request;
	struct alfred_push_data_v0 *push;
	struct alfred_status_v0 *status;
	struct alfred_tlv *tlv;
	struct alfred_data *data;
	int ret, len, data_len;
	json_t *root, *value;

	if (unix_sock_open_client(globals, ALFRED_SOCK_PATH))
		return -1;

	request = (struct alfred_request_v0 *)buf;
	len = sizeof(*request);

	request->header.type = ALFRED_REQUEST;
	request->header.version = ALFRED_VERSION;
	request->header.length = sizeof(*request) - sizeof(request->header);
	request->header.length = htons(request->header.length);
	request->requested_type = globals->clientmode_arg;
	request->tx_id = get_random_id();

	ret = write(globals->unix_sock, buf, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	root = json_object();

	push = (struct alfred_push_data_v0 *)buf;
	tlv = (struct alfred_tlv *)buf;
	while ((ret = read(globals->unix_sock, buf, sizeof(*tlv))) > 0) {
		if (ret < (int)sizeof(*tlv))
			break;

		if (tlv->type == ALFRED_STATUS_ERROR)
			goto recv_err;

		if (tlv->type != ALFRED_PUSH_DATA)
			break;

		/* read the rest of the header */
		ret = read(globals->unix_sock, buf + sizeof(*tlv),
			   sizeof(*push) - sizeof(*tlv));

		/* too short */
		if (ret < (int)(sizeof(*push) - (int)sizeof(*tlv)))
			break;

		/* read the rest of the header */
		ret = read(globals->unix_sock, buf + sizeof(*push),
			   sizeof(*data));

		data = push->data;
		data_len = ntohs(data->header.length);

		/* would it fit? it should! */
		if (data_len > (int)(sizeof(buf) - sizeof(*push)))
			break;

		/* read the data */
		ret = read(globals->unix_sock,
			   buf + sizeof(*push) + sizeof(*data), data_len);

		/* again too short */
		if (ret < data_len)
			break;

		pos = data->data;

		char id[19];
		sprintf(id, "%02x:%02x:%02x:%02x:%02x:%02x",
		       data->source[0], data->source[1],
		       data->source[2], data->source[3],
		       data->source[4], data->source[5]);

		value = NULL;

		/* Try parsing data as JSON. */
		json_error_t error;
		value = json_loadb((char*)pos, data_len, 0, &error);

		if (value == NULL && memchr(pos, 0, data_len) == NULL) {
			/* data was not JSON and there is no nullbyte in data.
			 * Try expressing data as JSON string. */

			char *tmp;
			tmp = calloc(data_len, sizeof(char));
			strncpy(tmp, (char*)pos, data_len);
			value = json_string(tmp);
			free(tmp);
		}

		if (value == NULL) {
			/* Data could not be expressed as string.
			 * Create an array of integers. */

			value = json_array();
			while(data_len--)
				json_array_append_new(value, json_integer(*pos++));
		}

		json_object_set_new(root, id, value);
	}

	json_dumpf(root, stdout, JSON_INDENT(2));

	json_decref(root);

	unix_sock_close(globals);

	return 0;

recv_err:
	json_decref(root);

	/* read the rest of the status message */
	ret = read(globals->unix_sock, buf + sizeof(*tlv),
		   sizeof(*status) - sizeof(*tlv));

	/* too short */
	if (ret < (int)(sizeof(*status) - sizeof(*tlv)))
		return -1;

	status = (struct alfred_status_v0 *)buf;
	fprintf(stderr, "Request failed with %d\n", status->tx.seqno);

	return status->tx.seqno;;
}

int alfred_client_set_data(struct globals *globals)
{
	unsigned char buf[MAX_PAYLOAD];
	struct alfred_push_data_v0 *push;
	struct alfred_data *data;
	int ret, len;

	if (unix_sock_open_client(globals, ALFRED_SOCK_PATH))
		return -1;

	push = (struct alfred_push_data_v0 *)buf;
	data = push->data;
	len = sizeof(*push) + sizeof(*data);
	while (!feof(stdin)) {
		ret = fread(&buf[len], 1, sizeof(buf) - len, stdin);
		len += ret;

		if (sizeof(buf) == len)
			break;
	}

	push->header.type = ALFRED_PUSH_DATA;
	push->header.version = ALFRED_VERSION;
	push->header.length = htons(len - sizeof(push->header));
	push->tx.id = get_random_id();
	push->tx.seqno = htons(0);

	/* we leave data->source "empty" */
	memset(data->source, 0, sizeof(data->source));
	data->header.type = globals->clientmode_arg;
	data->header.version = globals->clientmode_version;
	data->header.length = htons(len - sizeof(*push) - sizeof(*data));

	ret = write(globals->unix_sock, buf, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	unix_sock_close(globals);
	return 0;
}
