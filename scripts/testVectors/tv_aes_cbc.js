﻿//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

var testVectorsAESCBC = {
    "AES-CBC-128": [
    {
        key: "00000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "66E94BD4EF8A2C3B884CFA59CA342B2E9434DEC2D00FDAC765F00C0C11628CD1"
    }
    ],
    "AES-CBC-192": [
    {
        key: "000000000000000000000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "AAE06992ACBF52A3E8F4A96EC9300BD71045BE567103016AC50B21B86FC5457E"
    }
    ],
    "AES-CBC-256": [
    {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "DC95C078A2408989AD48A21492842087F3C003DDC4A7B8A94BAEDFFC3D214C38"
    }
    ]
}