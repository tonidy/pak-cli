{
  "targets": [
    {
      "target_name": "secure_enclave_native",
      "sources": [
        "src/secure_enclave_addon.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!@(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "MACOSX_DEPLOYMENT_TARGET": "11.0",
            "OTHER_CPLUSPLUSFLAGS": [
              "-std=c++17",
              "-stdlib=libc++"
            ],
            "OTHER_LDFLAGS": [
              "-Wl,-rpath,<(module_root_dir)/SecureEnclaveSwift/.build/release"
            ]
          },
          "libraries": [
            "-framework Security",
            "-framework LocalAuthentication",
            "-framework Foundation",
            "<(module_root_dir)/SecureEnclaveSwift/.build/release/libSecureEnclaveSwift.dylib"
          ]
        }]
      ]
    }
  ]
} 