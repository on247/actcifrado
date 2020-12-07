#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sodium.h>
#include <string.h>

off_t fsize(char *filename) {
    struct stat st; 

    if (stat(filename, &st) == 0)
        return st.st_size;

    return -1; 
}

void print_hex(char * str){
    while (*str != 0) {
        printf("%02x", (unsigned char) *str);
        str++;
    }
    printf("\n");
}

unsigned char hex2bin( const char *s )
{
    int ret=0;
    int i;
    for( i=0; i<2; i++ )
    {
        char c = *s++;
        int n=0;
        if( '0'<=c && c<='9' )
            n = c-'0';
        else if( 'a'<=c && c<='f' )
            n = 10 + c-'a';
        else if( 'A'<=c && c<='F' )
            n = 10 + c-'A';
        ret = n + ret*16;
    }
    return (unsigned char)ret;
}


void strhex(unsigned char * dest,char * src){
  unsigned char zero = '0';
  while (*src != 0) {
     char digit[2]={src[0],src[1]};
     *dest = hex2bin(digit);
    src+=2;
    dest++;
  }
} 

  
int main(int argc,char **argv)
{
   char *filename = argv[1];
   if(argc<2){
       printf("./actcifrado modo archivo [clave]");
       return 1;
   }
   FILE *file;
   file = fopen(filename,"rb");

   if(file){
      if(strcmp(argv[2],"cifrar")==0){
        off_t size = fsize(filename);
        char *message = (char *) malloc(sizeof(char) * size);
        size_t bytesread = fread(message,sizeof(char),size,file);
        unsigned long long messageSize = (unsigned long long) bytesread;
        printf("%lu bytes leidos\n",bytesread);
        printf("Generando clave privada \n");
        if (sodium_init() < 0) return 1;
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        crypto_secretstream_xchacha20poly1305_keygen(key);
        crypto_secretstream_xchacha20poly1305_state state;
        crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
        printf("PRIV:\n");
        print_hex(key);
        printf("HEADER:\n");
        print_hex(header);

        long long unsigned int cyphertext_len;
        unsigned char  cyphertext_content[messageSize + crypto_secretstream_xchacha20poly1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
        crypto_secretstream_xchacha20poly1305_push(&state, cyphertext_content, &cyphertext_len, message, messageSize,NULL, 0, 0);

        printf("Archivo cifrado.\n");

        int filename_len = strlen(filename);
        int outfilename_len = filename_len + 9;
        char outfilename[outfilename_len];
        sprintf(outfilename,"%s.cifrado",filename);
        FILE * file_encrypted = fopen(outfilename,"wb");
        // escribir header
        size_t bytesout = fwrite(header,sizeof(char),crypto_secretstream_xchacha20poly1305_HEADERBYTES,file_encrypted);
        // escribir clave
        bytesout = fwrite(cyphertext_content,sizeof(char),cyphertext_len,file_encrypted);


        if(bytesout){
          printf("Archivo cifrado guardado en");
          printf(" %s\n",outfilename);
        }
        else{
          printf("error al guardar.\n");
        }
      }
      if(strcmp(argv[2],"descifrar")==0){
        if (sodium_init() < 0) return 1;
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        strhex(key,argv[3]);
        printf("PRIV:\n");
        print_hex(key);

        char *header= (char *) malloc(sizeof(char) * crypto_secretstream_xchacha20poly1305_HEADERBYTES);
        off_t size = fsize(filename);
        size_t bytesheader= fread(header,sizeof(char),crypto_secretstream_xchacha20poly1305_HEADERBYTES,file);
        printf("HEADER:\n");
        print_hex(header);
        
        char * cyphertext = (char *) malloc(sizeof(char) * (size-bytesheader));
        size_t bytescontent = fread(cyphertext,sizeof(char), (size-bytesheader),file);
      
        crypto_secretstream_xchacha20poly1305_state state;
        crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key);
        char decrypted_content[bytescontent];
        long long unsigned  decrypted_len;
        if (crypto_secretstream_xchacha20poly1305_pull(&state, decrypted_content, &decrypted_len, NULL, cyphertext, bytescontent, NULL, 0) == 0) {
          printf("Archivo descifrado correctamente\n");
          int filename_len=strlen(filename);
          int outfilename_len=filename_len-8;
          char outfilename[outfilename_len];
          strncpy(outfilename,filename,outfilename_len);
          outfilename[outfilename_len]='\0';
          FILE * file_decrypted = fopen(outfilename,"wb");
          size_t bytesout = fwrite(decrypted_content,sizeof(char),decrypted_len,file_decrypted);
          if(bytesout){
            printf("Archivo guardado.\n");
          }
          else{
            printf("error al guardar.\n");
          }
        }
        else{
            printf("Error al descifrar\n");
        }
      }
   }

   else{
       printf("Error al abrir archivo");
   }
  
   return 0;
}