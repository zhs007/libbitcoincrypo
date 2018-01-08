{
    "targets": [
        {
            "target_name": "bitcoincrypo",
            "sources": [
                "src/libbitcoincrypo/Base58Check.cpp", 
                "src/libbitcoincrypo/CurvePoint.cpp",
                "src/libbitcoincrypo/Ecdsa.cpp",
                "src/libbitcoincrypo/FieldInt.cpp",
                "src/libbitcoincrypo/Ripemd160.cpp",
                "src/libbitcoincrypo/Sha256.cpp",
                "src/libbitcoincrypo/Sha256Hash.cpp",
                "src/libbitcoincrypo/Sha512.cpp",
                "src/libbitcoincrypo/Uint256.cpp",
                "src/libbitcoincrypo/Utils.cpp" 
            ],
            "include_dirs" : [
 	 			"<!(node -e \"require('nan')\")"
			]
        }
    ],
}