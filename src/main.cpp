#include "libbitcoincrypo.h"

NAN_MODULE_INIT(Init) {
    Nan::Set(target, Nan::New("cmpUint256").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(cmpUint256)).ToLocalChecked());

    Nan::Set(target, Nan::New("sha256").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(sha256)).ToLocalChecked());

    Nan::Set(target, Nan::New("prikey2pubkey").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(prikey2pubkey)).ToLocalChecked());

    Nan::Set(target, Nan::New("ripemd160").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(ripemd160)).ToLocalChecked());

    Nan::Set(target, Nan::New("isValidPriKey").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(isValidPriKey)).ToLocalChecked());

    Nan::Set(target, Nan::New("prikey2base58check").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(prikey2base58check)).ToLocalChecked());

    Nan::Set(target, Nan::New("pubkeyhash2base58check").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(pubkeyhash2base58check)).ToLocalChecked());                
}

NODE_MODULE(libbitcoincrypo, Init)