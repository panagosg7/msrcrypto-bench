//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

module operations {

	export var register = function (operationType: string, algorithmName, functionToCall) {

		if (!(<any>operations)[operationType]) {
			(<any>operations)[operationType] = {};
		}

		var op = (<any>operations)[operationType];

		if (!op[algorithmName]) {
			op[algorithmName] = functionToCall;
		}

	}

	export var exists = function (operationType, algorithmName) {
		if (!(<any>operations)[operationType]) {
			return false;
		}

		return ((<any>operations)[operationType][algorithmName]) ? true : false;
	}

}