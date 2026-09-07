#include <assert.h>
#include <string.h>

#include "destool_cli.h"

static bool parse(const char *const *input,int count,destool_cli_options *options,
                  std::string *error)
{
    char *argv[16];
    for (int i=0;i<count;i++) argv[i]=const_cast<char *>(input[i]);
    return destool_parse_command_line(count,argv,options,error);
}

int main(void)
{
    unsigned int number=99;
    assert(destool_parse_uint("0",&number) && number==0);
    assert(destool_parse_uint("32",&number) && number==32);
    assert(!destool_parse_uint("",&number));
    assert(!destool_parse_uint("+1",&number));
    assert(!destool_parse_uint(" 1",&number));
    assert(!destool_parse_uint("1x",&number));
    assert(!destool_parse_uint("999999999999999999999",&number));

    uint8_t block[8];
    assert(destool_parse_hex("0123456789aBcDeF",8,block));
    const uint8_t expected[8]={1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    assert(memcmp(block,expected,8)==0);
    assert(!destool_parse_hex("0123",8,block));
    assert(!destool_parse_hex("0123456789ABCDEG",8,block));

    const char *valid[]={"destool","0123456789ABCDEF","85E813540F0AB405",
                         "-a","3","-l","2","-t","4","-s","4141","-e","5A5A"};
    destool_cli_options options;
    std::string error;
    assert(parse(valid,(int)(sizeof(valid)/sizeof(valid[0])),&options,&error));
    destool_search_spec search;
    assert(destool_make_search_spec(options,&search,&error));
    assert(search.alphabet_id==3 && search.key_length==2 && search.thread_count==4);
    uint8_t key[7]={0}; uint64_t cbn=0;
    assert(destool_parse_hex("4141",2,key));
    assert(destool_key_to_cbn(key,3,2,&cbn) && cbn==search.start_cbn);
    assert(destool_parse_hex("5A5A",2,key));
    assert(destool_key_to_cbn(key,3,2,&cbn) && cbn+1U==search.end_cbn);

    const char *duplicate[]={"destool","0000000000000000","0000000000000000",
                             "-a","2","-a","3","-l","1"};
    assert(!parse(duplicate,(int)(sizeof(duplicate)/sizeof(duplicate[0])),&options,&error));
    const char *unknown[]={"destool","0","0","--wat"};
    assert(!parse(unknown,(int)(sizeof(unknown)/sizeof(unknown[0])),&options,&error));

    const char *missing_required[]={"destool","0000000000000000",
                                    "0000000000000000","-a","2"};
    assert(!parse(missing_required,
                  (int)(sizeof(missing_required)/sizeof(missing_required[0])),
                  &options,&error));
    const char *extra[]={"destool","0000000000000000","0000000000000000",
                         "extra","-a","2","-l","1"};
    assert(!parse(extra,(int)(sizeof(extra)/sizeof(extra[0])),&options,&error));

    const char *bad_values[][7]={
      {"destool","0000000000000000","0000000000000000","-a","0","-l","1"},
      {"destool","0000000000000000","0000000000000000","-a","8","-l","1"},
      {"destool","0000000000000000","0000000000000000","-a","2","-l","0"},
      {"destool","0000000000000000","0000000000000000","-a","2","-l","8"},
      {"destool","0000000000000000","0000000000000000","-a","2","-t","0"},
      {"destool","0000000000000000","0000000000000000","-a","2","-t","33"}};
    for (size_t i=0;i<sizeof(bad_values)/sizeof(bad_values[0]);i++) {
      const int count=(i<4)?7:7;
      /* Thread cases deliberately omit -l only after parsing the bad value. */
      if (i>=4) {
        const char *thread_case[]={"destool","0000000000000000","0000000000000000",
                                   "-a","2","-l","1","-t",i==4?"0":"33"};
        assert(parse(thread_case,
                     (int)(sizeof(thread_case)/sizeof(thread_case[0])),
                     &options,&error));
      } else assert(parse(bad_values[i],count,&options,&error));
      destool_search_spec invalid;
      assert(!destool_make_search_spec(options,&invalid,&error));
    }

    const char *bad_range[]={"destool","0000000000000000","0000000000000000",
                             "-a","3","-l","2","-s","41"};
    assert(parse(bad_range,(int)(sizeof(bad_range)/sizeof(bad_range[0])),
                 &options,&error));
    assert(!destool_make_search_spec(options,&search,&error));

    assert(strcmp(destool_alphabet_name(7),"0-9,a-z,A-Z")==0);
    const uint8_t binary[]={0,'A','\\','"',0xff};
    assert(destool_format_hex(binary,5)=="00415C22FF");
    assert(destool_format_escaped(binary,5)=="\"\\x00A\\\\\\\"\\xFF\"");
    uint8_t material[7]={'P','A','S','S','W','D',0},des_key[8];
    destool_expand_des_key(material,des_key);
    for (size_t i=0;i<8;i++) {
      unsigned int ones=0;
      for (unsigned int bit=0;bit<8;bit++) ones+=(des_key[i]>>bit)&1U;
      assert((ones&1U)==1U);
    }
    return 0;
}
