/* Comp30023 Project 2
 * Jin Wei loh 831730
 * 23/05/18
 */

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#define VALID 1
#define INVALID 0
#define CSV_COLUMNS 2
#define MINIMUM_RSA_KEY_LENGTH 2048
#define DEFAULT_SIZE 256

int validate_dates(X509 *cert);
int validate_common_name(X509 *cert, char *certurl);
int validate_subject_alternative_name(X509 *cert, char *certurl);
int compare_domain_names(char *name, char*certurl);
int validate_rsa_key_length(X509 *cert);
int check_cert_validity(X509 *cert, char* certurl);
int validate_enhanced_key_usage(X509* cert);
int validate_basic_constraints(X509* cert);
char* get_extension_value(X509 *cert, int NID);
char** split_string(char* string, char* delimiter);

int main(int argc, char *argv[]) {

  char* filename;
  char line[DEFAULT_SIZE];
  char* certfile;
  char* certurl;

  //initialise openSSL
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  BIO *certificate_bio = NULL;
  X509 *cert = NULL;


  // check if enough arguments are provided
  if(argc < 2){
    fprintf(stderr, "Invalid number of arguments");
    exit(EXIT_FAILURE);
  }

  // open input csv file
  filename = argv[1];
  FILE* fp_in = fopen(filename, "r");

  // open csv output file to write on
  FILE* fp_output;
  char *output_filename = "output.csv";
  fp_output = fopen(output_filename, "w+");

  // read csv
  while(fgets(line, DEFAULT_SIZE, fp_in)){

    //get rid of newline
    line[strlen(line)-1] = '\0';

    //split the line with a comma as a delimiter
    char **string_array = split_string(line, ",");

    certfile = string_array[0];
    certurl = string_array[1];

    printf("%s\n",certfile );
    printf("%s\n",certurl );


    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, certfile)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }


    fprintf(fp_output,"%s,%s,%d\n", certfile, certurl,
                                  check_cert_validity(cert,certurl));

    X509_free(cert);
    BIO_free_all(certificate_bio);

  }
  fclose(fp_in);
  exit(0);
}


// checking if the not before and not after date are valid
int validate_dates(X509 *cert){

    int valid = INVALID;
    int before_daydiff;
    int before_secdiff;
    int after_daydiff;
    int after_secdiff;
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    // check the difference in day and seconds for the not before date
    ASN1_TIME_diff(&before_daydiff, &before_secdiff, not_before, NULL);
    // check the difference in day and seconds for the not after date
    ASN1_TIME_diff(&after_daydiff, &after_secdiff, NULL, not_after);

    // if daydiff or secdiff is negative, it means its not valid
    if(before_daydiff <= 0 || before_secdiff <= 0){
      printf("Invalid not before date\n");
    }
    else if(after_daydiff <= 0 || after_secdiff <= 0){
      printf("Invalid not after date\n");
    }
    // valid dates
    else {
      valid = VALID;
    }

    return valid;
}

// validate common name
int validate_common_name(X509 *cert, char *certurl){

    int valid = INVALID;
    X509_NAME *subject_name = X509_get_subject_name(cert);
    char common_name[DEFAULT_SIZE] = "Subject Common Name NOT FOUND";
    X509_NAME_get_text_by_NID(subject_name, NID_commonName,
                              common_name, DEFAULT_SIZE);

    if (compare_domain_names(common_name,certurl) == VALID){
        valid = VALID;
    }
    return valid;
}


// check if subject alternative name is present and valid
int validate_subject_alternative_name(X509 *cert, char *certurl){
  int stack_len;
  int i = 0;
  int valid = INVALID;
  char* domain_name;

  // get all the alternaive names
  STACK_OF(GENERAL_NAME) *sub_alt_name = X509_get_ext_d2i(
                                         cert,NID_subject_alt_name, NULL, NULL);

  // check if given certurl is present in any of the alternative names
  if (sub_alt_name != NULL){

    stack_len = sk_GENERAL_NAME_num(sub_alt_name);

    while (i < stack_len) {

      const GENERAL_NAME *name = sk_GENERAL_NAME_value(sub_alt_name, i);

      if (name-> type == GEN_DNS){

        domain_name = (char *) ASN1_STRING_data(name->d.dNSName);
        if (compare_domain_names(domain_name,certurl) == VALID){
            valid = VALID;
            break;
        }
      }

      i += 1;

    }

  }

  return valid;
}

// helper function to compare two strings in both cases of having wildcards
// or not having
int compare_domain_names(char *name, char*certurl){

  int name_len = strlen(name);
  int certurl_len = strlen(certurl);
  int wildcard = 0;

  // check if wildcard present
  if (strstr(name,"*") != NULL){
    wildcard = 1;
  }
  // compare the strings after the wildcard or www etc.
  int compare = strcmp(&name[wildcard],
                       &certurl[certurl_len - name_len + wildcard]);
  if (compare != 0){
      return INVALID;
  }

  return VALID;

}


// get extension value
// code adapted from certexample.c from Chris
char* get_extension_value(X509 *cert, int NID){

  BUF_MEM *bptr = NULL;
  char *buf = NULL;

  X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID, -1));
  // check if extension in cert
  if(!ex){
      return NULL;
  }

  BIO *bio = BIO_new(BIO_s_mem());

  if (!X509V3_EXT_print(bio, ex, 0, 0))
  {
      fprintf(stderr, "Error in reading extensions");
      return NULL;
  }

  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bptr);

  //bptr->data is not NULL terminated - add null character (MAKE PRINTABLE)
  buf = (char *)malloc((bptr->length + 1) * sizeof(char));
  memcpy(buf, bptr->data, bptr->length);
  buf[bptr->length] = '\0';

  BIO_free_all(bio);

  return buf;

}

// Check if the basic constraints extension contains "CA:FALSE"
int validate_basic_constraints(X509* cert) {

  int valid = INVALID;
	char* basic_constraint = get_extension_value(cert, NID_basic_constraints);
	if (basic_constraint != NULL) {
		if (strstr(basic_constraint,"CA:FALSE")){
      valid = VALID;
    }
  }

	free(basic_constraint);

  return valid;
}

// Checks if the enhanced key usage includes
// "TLS Web Server Authentication"
int validate_enhanced_key_usage(X509* cert) {

  int valid = INVALID;
	char* ext_key_usage = get_extension_value(cert, NID_ext_key_usage);
	if (ext_key_usage != NULL) {
    if (strstr(ext_key_usage,"TLS Web Server Authentication")){
      valid = VALID;
    }
	}
	return valid;
}

// validate the minimum RSA key Length
int validate_rsa_key_length(X509 *cert){

  int valid = INVALID;
  EVP_PKEY *pub_key = X509_get_pubkey(cert);
  RSA *rsa_key = EVP_PKEY_get1_RSA(pub_key);

  int key_length = BN_num_bits(rsa_key->n);

  if (key_length >= MINIMUM_RSA_KEY_LENGTH){
      valid = VALID;
  }

  RSA_free(rsa_key);
  return valid;
}

// check overall validity of file
int check_cert_validity(X509 *cert, char* certurl){

  int overall_validity = VALID;

  // check validity of not before and not after date
  if (validate_dates(cert) != VALID){
    overall_validity = INVALID;
  }



  // check validity of RSA key length
  if (validate_rsa_key_length(cert) != VALID){
    overall_validity = INVALID;
    printf("Invalid RSA key length\n");
  }


  // check validity of basic constraints
  if (validate_basic_constraints(cert) != VALID){
    overall_validity = INVALID;
    printf("Basic constraints does not include CA:False\n");
  }


  // check validity of enhanced key usage
  if (validate_enhanced_key_usage(cert) != VALID){
    overall_validity = INVALID;
    printf("Key Usage does not include TLS Web Server Authentication\n");
  }

  // check if domain name present in ethier common name or its
  // alternative name
  if((validate_common_name(cert,certurl) != VALID) &&
     (validate_subject_alternative_name(cert,certurl) != VALID)){
    overall_validity = INVALID;

    if (validate_common_name(cert,certurl) != VALID){
      printf("Common name FAIL\n");
    }
    if (validate_subject_alternative_name(cert,certurl) != VALID){
      printf("Subject alternative name FAIL\n");
    }

  }

  return overall_validity;

}


// helper function to split string
// code adapted from stack overflow user hmjd
// https://stackoverflow.com/questions/9210528/split-string-with-delimiters-in-c
char** split_string(char* string, char* delimiter){

    char** string_array;
    char* temp_copy = string;
    // since the array needs to store certfile name and certurl
    string_array = malloc(sizeof(char*) * CSV_COLUMNS);
    if (string_array){
        int counter  = 0;
        char* temp_token = strtok(temp_copy, delimiter);
        // storing the string value into array
        while (temp_token){
            *(string_array + counter++) = strdup(temp_token);
            temp_token = strtok(NULL, delimiter);
        }
        
    }

    return string_array;
}
