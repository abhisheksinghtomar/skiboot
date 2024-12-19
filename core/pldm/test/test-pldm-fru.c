// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#include "test-pldm-common.c"

#define FRU1_MODEL "9309-24B"
#define FRU1_SERIAL "1234567"
#define FRU1_NAME "System"
#define FRU1_VERSION "fw10xx-test"

enum fru_special_case_code  {
	NORMAL_CASE = 0x00,
	FRU_TABLE_TRANSFER_FLAG_ERROR = 0x01,
	FRU_TABLE_RESPONSE_ERROR = 0x02,
};
enum fru_special_case_code  fru_special_case = NORMAL_CASE;



struct pldm_fru_record_data_format fru1_test = {
	.record_set_id = 1,
	.record_type = PLDM_FRU_RECORD_TYPE_GENERAL,
	.num_fru_fields = 4,
	.encoding_type = PLDM_FRU_ENCODING_ASCII
};

#define FRU2_NAME "FRU_test"
#define FRU2_LOCATION_CODE "U78AA.mmm"
struct pldm_fru_record_data_format fru2_test = {
	.record_set_id = 2,
	.record_type = PLDM_FRU_RECORD_TYPE_OEM,
	.num_fru_fields = 2,
	.encoding_type = PLDM_FRU_ENCODING_ASCII
};


// Temp call not for UPSTREAM
static void print_tlv(uint8_t *tlvs, int num_tlv)
{
	int size = 0, i;
	struct pldm_fru_record_tlv *tlv;
	printf(" -------------- INSIDE %s -----------------\n",__func__);

	for (i = 1; i <= num_tlv; i++) {
		tlv = (struct pldm_fru_record_tlv *)(tlvs + size);
		printf("TLV %d \n type = %d \n len=%d \nvalue=%.*s\n\n",
				i, tlv->type, tlv->length, tlv->length, tlv->value);
		size += sizeof(struct pldm_fru_record_tlv) + tlv->length - 1;
	}
}


// Temp call not for UPSTREAM
//show_fru_records(fru_table, size - record_len);
static void show_fru_records(uint8_t *fru_table, size_t offset) {
	struct pldm_fru_record_data_format *record;
		
	record = (struct pldm_fru_record_data_format *)(fru_table + offset);

	printf("================== FRU RECORD ============\n");
	printf("setid = %d\n record type = %d \n num fru = %d \n encoding type =%d\n",
			record->record_set_id, record->record_type,
			record->num_fru_fields, record->encoding_type);
	print_tlv((uint8_t *)&record->tlvs, record->num_fru_fields);
}

static int encode_tlv_size(uint8_t *tlvs, size_t *size, uint8_t type, uint8_t length, const uint8_t *value){

	struct pldm_fru_record_tlv *tlv;

	tlv = (struct pldm_fru_record_tlv *)(tlvs + *size);
	tlv->type = type;
	tlv->length = length;
	memcpy(tlv->value, value, tlv->length);
	*size += sizeof(struct pldm_fru_record_tlv) + tlv->length - 1;

	return OPAL_SUCCESS;
}

static int get_test_fru_table(uint8_t **fru_table, size_t *fru_table_len)
{
	int rc;
	size_t record_len;
	uint8_t *tlvs_record1;
	uint8_t *tlvs_record2;
	size_t tlvs_record1_len = 0;
	size_t tlvs_record2_len = 0;
	size_t size;


	// FRU 1 data as have 4 tlv
	tlvs_record1_len += 4*(sizeof(struct
				pldm_fru_record_tlv) -1);
	tlvs_record1_len += strlen(FRU1_MODEL) + strlen(FRU1_SERIAL)
		+ strlen(FRU1_NAME) + strlen(FRU1_VERSION);

	printf("%s :: FRU1 TOTAL LENGTH = %d\n",__func__, tlvs_record1_len);
	tlvs_record1 = malloc(tlvs_record1_len);
	if (tlvs_record1 == NULL) {
		perror("PLDM_TEST malloc");
		return OPAL_RESOURCE;
	}
	size = 0;
	encode_tlv_size(tlvs_record1, &size, PLDM_FRU_FIELD_TYPE_MODEL,
			strlen(FRU1_MODEL), FRU1_MODEL);
	encode_tlv_size(tlvs_record1, &size, PLDM_FRU_FIELD_TYPE_SN,
			strlen(FRU1_SERIAL), FRU1_SERIAL);
	encode_tlv_size(tlvs_record1, &size, PLDM_FRU_FIELD_TYPE_NAME,
			strlen(FRU1_NAME), FRU1_NAME);
	encode_tlv_size(tlvs_record1, &size, PLDM_FRU_FIELD_TYPE_VERSION,
			strlen(FRU1_VERSION),FRU1_VERSION);

	print_tlv(tlvs_record1,4);
	if(size != tlvs_record1_len) {
		free(tlvs_record1);
		return OPAL_PARAMETER;
	}


	//  FRU 2 data as have 2 tlv
	tlvs_record2_len += 2*(sizeof(struct
				pldm_fru_record_tlv) -1);
	tlvs_record2_len += strlen(FRU2_NAME) + strlen(FRU2_LOCATION_CODE);

	printf("%s :: FRU2 TOTAL LENGTH = %d\n",__func__, tlvs_record2_len);
	tlvs_record2 = malloc(tlvs_record2_len);
	if (tlvs_record2 == NULL) {
		perror("PLDM_TEST malloc");
		free(tlvs_record1);
		return OPAL_RESOURCE;
	}
	size = 0;
	encode_tlv_size(tlvs_record2, &size, PLDM_FRU_FIELD_TYPE_NAME,
			strlen(FRU2_NAME), FRU2_NAME);
	encode_tlv_size(tlvs_record2, &size, 0XFE, strlen(FRU2_LOCATION_CODE),
			FRU2_LOCATION_CODE);

	print_tlv(tlvs_record2, 2);
	if(size != tlvs_record2_len) {
		free(tlvs_record1);
		free(tlvs_record2);
		return OPAL_PARAMETER;
	}


	*fru_table_len = 2 * (sizeof(struct pldm_fru_record_data_format) - 1)
		+ tlvs_record1_len + tlvs_record2_len;

	*fru_table = malloc(*fru_table_len);	
	if (*fru_table == NULL) {
		perror("PLDM_TEST malloc");
		free(tlvs_record1);
		free(tlvs_record2);
		return OPAL_RESOURCE;
	}
	size = 0;

	/*
	 * Encode FRU 1 record
	 */
	record_len = sizeof(struct pldm_fru_record_data_format) +
		tlvs_record1_len - sizeof(struct pldm_fru_record_tlv);
	
	rc = encode_fru_record(*fru_table,
			size + record_len, &size, fru1_test.record_set_id,
			fru1_test.record_type, fru1_test.num_fru_fields,
			fru1_test.encoding_type, tlvs_record1, tlvs_record1_len);
	if (rc != OPAL_SUCCESS) {
		perror("PLDM_TEST encode_fru_record");
		free(tlvs_record1);
		free(tlvs_record2);
		return OPAL_PARAMETER;
	}
	printf("ENCODE FRU 1 SUCCESS =%d size=%d\n",rc,size);
	
	/*
	 * Encode FRU 2 record
	 */
	record_len = sizeof(struct pldm_fru_record_data_format) +
		tlvs_record2_len - sizeof(struct pldm_fru_record_tlv);
	rc = encode_fru_record(*fru_table,
			size + record_len, &size, fru2_test.record_set_id,
			fru2_test.record_type, fru2_test.num_fru_fields,
			fru2_test.encoding_type, tlvs_record2, tlvs_record2_len);
	if (rc != OPAL_SUCCESS) {
		perror("PLDM_TEST encode_fru_record");
		free(tlvs_record1);
		free(tlvs_record2);
		return OPAL_PARAMETER;
	}
	printf("ENCODE FRU 2 SUCCESS =%d size=%d\n",rc,size);

	// Temp call not for UPSTREAM
	show_fru_records(*fru_table, 0);
	show_fru_records(*fru_table, size - record_len);
	
	free(tlvs_record1);
	free(tlvs_record2);
	return OPAL_SUCCESS;
}


/*
 * This function duplicates BMC functionality for Pldm self test
 * it handle PLDM_REQUEST for PLDM_PLATFORM and reply with appropriate
 * PLDM_RESPONSE message
 */
int pldm_test_reply_request_fru(void *request_msg, size_t request_len,
		void **response_msg, size_t *response_len)
{
	int rc = 0;
	int  payload_len = 0, completion_code = PLDM_SUCCESS;
	uint32_t data_transfer_handle, next_data_transfer_handle;
	uint8_t transfer_operation_flag;
	uint8_t *fru_table;
	size_t fru_table_len;
	struct pldm_get_fru_record_table_resp *resp_payload;

	/* check pldm command received and reply with appropriate pldm response message */
	switch (((struct pldm_msg *)request_msg)->hdr.command) {
	case PLDM_GET_FRU_RECORD_TABLE:
		payload_len = request_len - sizeof(struct pldm_msg_hdr);
		rc = decode_get_fru_record_table_req(request_msg, payload_len,
				&data_transfer_handle, &transfer_operation_flag);
		if (rc != PLDM_SUCCESS)
			return rc;
		
		rc = get_test_fru_table(&fru_table, &fru_table_len);
		if (rc != OPAL_SUCCESS)
			return rc;
		
		payload_len = 
			(sizeof(struct pldm_get_fru_record_table_resp) - 1)
			+ fru_table_len;
		
		*response_len = sizeof(struct pldm_msg_hdr)
			+ payload_len;

		*response_msg = malloc(*response_len);
		if (*response_msg == NULL) {
			perror("PLDM_TEST malloc");
			return OPAL_RESOURCE;
		}

		next_data_transfer_handle = PLDM_GET_NEXTPART;
		
		if (fru_special_case ==
				FRU_TABLE_TRANSFER_FLAG_ERROR)
			transfer_operation_flag = PLDM_START;
		else
			transfer_operation_flag = PLDM_START_AND_END;

		if (fru_special_case ==
				FRU_TABLE_RESPONSE_ERROR)
			completion_code = PLDM_START;

		rc = encode_get_fru_record_table_resp(
				((struct pldm_msg *)request_msg)->hdr.instance_id,
				completion_code, next_data_transfer_handle,
				transfer_operation_flag, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;
		
		resp_payload = (struct pldm_get_fru_record_table_resp *)
			((struct pldm_msg *)*response_msg)->payload;
		memcpy(resp_payload->fru_record_table_data, fru_table, fru_table_len);
		free(fru_table);
		
		return OPAL_SUCCESS;

	default:
	       return OPAL_PARAMETER;


	}

	return OPAL_SUCCESS;
}


int ast_mctp_message_tx(bool tag_owner __unused, uint8_t msg_tag __unused,
		uint8_t *msg, int len)
{
	uint8_t *pldm_received_msg = msg+1;
	void *response_msg;
	size_t response_len;
	int rc;

	if (msg[0] != 0x01) {
		printf("TEST : %s : request MCTP message type not set for PLDM\n", __func__);
		return OPAL_PARAMETER;
	}

	/* TEST Message TYPE: PLDM = 0x01 (000_0001b) as per MCTP - DSP0240 */
	if (((struct pldm_msg *)pldm_received_msg)->hdr.request == PLDM_RESPONSE)
		return OPAL_PARAMETER;

	/* Reply to requests */
	else if (((struct pldm_msg *)pldm_received_msg)->hdr.request == PLDM_REQUEST) {
		rc = pldm_test_reply_request_fru(pldm_received_msg, len-1,
				&response_msg, &response_len);
		if (rc != OPAL_SUCCESS)
			return rc;

		if (response_len <= 0)
			return OPAL_PARAMETER;

		pldm_mctp_message_rx(BMC_EID, tag_owner,
				msg_tag, response_msg,
				response_len);
		free(response_msg);
	}
	return OPAL_SUCCESS;

}


int test_pldm_fru_init_response_error(void)
{
	int rc;
	fru_special_case = FRU_TABLE_RESPONSE_ERROR; 
	rc = pldm_fru_init();
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_PARAMETER);
		fru_special_case = NORMAL_CASE; 
		return OPAL_PARAMETER;

	}
	fru_special_case = NORMAL_CASE; 
	return OPAL_SUCCESS;
}


int test_pldm_fru_init_transfer_flag_error(void)
{
	int rc;
	fru_special_case = FRU_TABLE_TRANSFER_FLAG_ERROR; 
	rc = pldm_fru_init();
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_PARAMETER);
		fru_special_case = NORMAL_CASE; 
		return OPAL_PARAMETER;

	}
	fru_special_case = NORMAL_CASE; 
	return OPAL_SUCCESS;
}

int test_pldm_fru_init(void)
{
	int rc;
	fru_special_case = NORMAL_CASE; 
	rc = pldm_fru_init();
	if (rc  != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;

	}
	return OPAL_SUCCESS;
}

int test_pldm_local_table(void)
{
	int rc;
	uint32_t table_length;
	uint16_t total_record_set_identifiers;
	uint16_t total_table_records;
	uint8_t *fru_record_table;

	fru_special_case = NORMAL_CASE; 
	
	pldm_fru_set_local_table(&table_length,
			&total_record_set_identifiers,
			&total_table_records);


	rc = pldm_fru_get_local_table((void**)&fru_record_table,
			&table_length);
	if (rc  != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;

	}

	show_fru_records(fru_record_table, 0);


	return OPAL_SUCCESS;
}


struct test_case {
	const char *name;
	int (*fn)(void);
};

#define TEST_CASE(x) { #x, x }

struct test_case test_cases[] = {
	TEST_CASE(test_pldm_fru_init_response_error),
	TEST_CASE(test_pldm_fru_init_transfer_flag_error),
	TEST_CASE(test_pldm_fru_init),
	TEST_CASE(test_pldm_local_table),
	{NULL, NULL}
};


int main(void)
{
	struct test_case *tc = &test_cases[0];
	int rc = 0;

	pldm_requester_init();

	do {
		rc = tc->fn();
		if (rc != OPAL_SUCCESS) {
			printf("PLDM FILEIO TEST :%s FAILED\n", tc->name);
			return -1;
		}
		printf("PLDM FILEIO TEST :%s PASSED\n", tc->name);
	} while ((++tc)->fn);
	// This is to kill thread running to take requests
	kill_poller();

	return OPAL_SUCCESS;
}

