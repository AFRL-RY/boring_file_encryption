cmake_minimum_required(VERSION 3.10)

# set the project name
project(bfe)

enable_testing()

include_directories(${CMAKE_SOURCE_DIR}/../boringssl/include)
link_directories(${CMAKE_SOURCE_DIR}/../boringssl/build/crypto ${CMAKE_SOURCE_DIR}/../boringssl/build/ssl)
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_INSTALL_BINDIR "/usr/local/bin")


# add the executable
add_executable(bfe bfe.c)
target_link_libraries(bfe ssl crypto pthread)
install(TARGETS bfe DESTINATION bin)


# ctests are below this line ==================================================

## Test the boringSSL library is built with FIPS
add_test(NAME boringssl_FIPS
        COMMAND /tmp/boringssl/build/tool/bssl isfips
        /tmp/boringssl/build/tool/)

## Testing of argument parsing
add_test(NAME argument_no_arguments
         COMMAND bfe
         ${CMAKE_SOURCE_DIR}/build/)

add_test(NAME argument_help
         COMMAND bfe -h
         ${CMAKE_SOURCE_DIR}/build/)
         
add_test(NAME argument_no_e_and_no_d
        COMMAND bfe -i some_file -o some_file
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_no_input
        COMMAND bfe -e -p 1234567890123456 -o some_file
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME argument_no_output
        COMMAND bfe -e -p 1234567890123456 -i some_file
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_e_and_d
        COMMAND bfe -p 1234567890123456 -i some_file -o some_file
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME argument_invalid
        COMMAND bfe -X
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME argument_input_file_not_exist
        COMMAND bfe -e -p test -i some_file_not_exist.txt -o some_file_not_exist.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_create_output_file
        COMMAND touch /tmp/bfe_output.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_output_file_exists
        COMMAND bfe -e -p 1234567890123456 -i ${CMAKE_SOURCE_DIR}/README.md -o /tmp/bfe_output.txt.enc
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME argument_input_and_output_same
        COMMAND bfe -e -p 1234567890123456 -i /tmp/bfe_output.txt.enc -o /tmp/bfe_output.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_password_not_specified
        COMMAND bfe -e -i ${CMAKE_SOURCE_DIR}/README.md -o /tmp/bfe_output_nogo.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME argument_password_not_16
        COMMAND bfe -e -p 123456789012345 -i ${CMAKE_SOURCE_DIR}/README.md -o /tmp/bfe_output_gtg.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
## Testing Encryption and Decryption

### Small file test
add_test(NAME ed_remove_out_file_enc
        COMMAND rm -rf /tmp/bfe_output.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME ed_remove_out_file_dec
        COMMAND rm -rf /tmp/bfe_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME encrypt
        COMMAND bfe -e -p 1234567890123456 -i ${CMAKE_SOURCE_DIR}/README.md -o /tmp/bfe_output.txt.enc
        ${CMAKE_SOURCE_DIR}/build/})
        
add_test(NAME decrypt_wrong_password
        COMMAND bfe -d -p 1234567890123457 -i /tmp/bfe_output.txt.enc -o /tmp/bfe_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME decrypt
        COMMAND bfe -d -p 1234567890123456 -i /tmp/bfe_output.txt.enc -o /tmp/bfe_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME compare_encrypt_decrypt
        COMMAND diff ${CMAKE_SOURCE_DIR}/README.md /tmp/bfe_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME ed_remove_all_files
        COMMAND rm -rf /tmp/bfe_output.txt.enc /tmp/bfe_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})
                
### Large file test
add_test(NAME ed_large_create_output_file
        COMMAND dd if=/dev/urandom of=/tmp/bfe_large_output.txt bs=64M count=32 # generate a random file to encrypt
        ${CMAKE_SOURCE_DIR/build/})

add_test(NAME encrypt_large
        COMMAND bfe -e -p 1234567890123456 -i /tmp/bfe_large_output.txt -o /tmp/bfe_large_output.txt.enc
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME decrypt_large
        COMMAND bfe -d -p 1234567890123456 -i /tmp/bfe_large_output.txt.enc -o /tmp/bfe_large_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME compare_encrypt_decrypt_large
        COMMAND diff /tmp/bfe_large_output.txt.dec /tmp/bfe_large_output.txt
        ${CMAKE_SOURCE_DIR/build/})
        
add_test(NAME ed_large_remove_all_files
        COMMAND rm -rf /tmp/bfe_large_output.txt /tmp/bfe_large_output.txt.enc /tmp/bfe_large_output.txt.dec
        ${CMAKE_SOURCE_DIR/build/})

set_tests_properties(argument_no_e_and_no_d 
                    argument_no_input 
                    argument_no_output 
                    argument_e_and_d
                    argument_invalid
                    argument_input_file_not_exist
                    argument_output_file_exists
                    argument_input_and_output_same
                    argument_password_not_specified
                    argument_password_not_16
                    decrypt_wrong_password
                    PROPERTIES WILL_FAIL TRUE)
