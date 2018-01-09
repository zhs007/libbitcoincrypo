#include <nan.h>

// cmpUint256(uint8arr0, uint8arr1)
// uint8arr0, uint8arr1 is uint8arr[32]
// return -1, 0, 1
NAN_METHOD(cmpUint256);

// sha256(uint8arr)
// return uint8arr[32]
NAN_METHOD(sha256);

// prikey2pubkey(uint8arr)
// return uintarr[65], [0] is 0x04
NAN_METHOD(prikey2pubkey);

// ripemd160(uint8arr)
// return uintarr[20]
NAN_METHOD(ripemd160);

// isValidPriKey(uint8arr)
// return bool
NAN_METHOD(isValidPriKey);

// prikey2base58check(uint8arr)
// return base58check
NAN_METHOD(prikey2base58check);

// pubkeyhash2base58check(uint8arr)
// return base58check
NAN_METHOD(pubkeyhash2base58check);