aux_source_directory(. DIR_LIB_SRCS)

find_package(OpenSSL REQUIRED)

add_library (sftp SHARED ${DIR_LIB_SRCS})

target_include_directories(sftp PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(sftp OpenSSL::Crypto)

#[[ ‘HMAC_CTX_new’, ‘HMAC_Init_ex’, ‘HMAC_CTX_free’, ... are deprecated since
   OpenSSL 3.0. I suppress the warning here because I don't want to modify 
   the source file and I don't think changing the version of openssl solves
   the security problem. ]]
target_compile_options(sftp PRIVATE -Wno-deprecated-declarations)