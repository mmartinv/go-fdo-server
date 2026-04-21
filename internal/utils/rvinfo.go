// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package utils

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// RVProtocolToString converts FDO protocol code to V2 protocol string
func RVProtocolToString(code uint8) (string, error) {
	switch code {
	case protocol.RVProtRest:
		return "rest", nil
	case protocol.RVProtHTTP:
		return "http", nil
	case protocol.RVProtHTTPS:
		return "https", nil
	case protocol.RVProtTCP:
		return "tcp", nil
	case protocol.RVProtTLS:
		return "tls", nil
	case protocol.RVProtCoapTCP:
		return "coap+tcp", nil
	case protocol.RVProtCoapUDP:
		return "coap", nil
	default:
		return "", fmt.Errorf("unknown protocol code: %d", code)
	}
}

// RVMediumToString converts FDO medium code to medium string
func RVMediumToString(code uint8) (string, error) {
	switch code {
	case protocol.RVMedWifiAll:
		return "wifi_all", nil
	case protocol.RVMedEthAll:
		return "eth_all", nil
	// Specific interfaces
	case 0:
		return "eth_0", nil
	case 1:
		return "eth_1", nil
	case 2:
		return "eth_2", nil
	case 3:
		return "eth_3", nil
	case 4:
		return "eth_4", nil
	case 5:
		return "eth_5", nil
	case 6:
		return "eth_6", nil
	case 7:
		return "eth_7", nil
	case 8:
		return "eth_8", nil
	case 9:
		return "eth_9", nil
	case 10:
		return "wifi_0", nil
	case 11:
		return "wifi_1", nil
	case 12:
		return "wifi_2", nil
	case 13:
		return "wifi_3", nil
	case 14:
		return "wifi_4", nil
	case 15:
		return "wifi_5", nil
	case 16:
		return "wifi_6", nil
	case 17:
		return "wifi_7", nil
	case 18:
		return "wifi_8", nil
	case 19:
		return "wifi_9", nil
	default:
		return "", fmt.Errorf("unknown medium code: %d", code)
	}
}

// RVProtocolFromString converts protocol string to protocol code
// This is the inverse of RVProtocolToString
func RVProtocolFromString(s string) (uint8, error) {
	switch s {
	case "rest":
		return uint8(protocol.RVProtRest), nil
	case "http":
		return uint8(protocol.RVProtHTTP), nil
	case "https":
		return uint8(protocol.RVProtHTTPS), nil
	case "tcp":
		return uint8(protocol.RVProtTCP), nil
	case "tls":
		return uint8(protocol.RVProtTLS), nil
	case "coap+tcp":
		return uint8(protocol.RVProtCoapTCP), nil
	case "coap":
		return uint8(protocol.RVProtCoapUDP), nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", s)
	}
}

// RVMediumFromString converts medium string to medium code
// This is the inverse of MediumStringFromCode
func RVMediumFromString(s string) (uint8, error) {
	switch s {
	case "wifi_all":
		return protocol.RVMedWifiAll, nil
	case "eth_all":
		return protocol.RVMedEthAll, nil
	// V2 API also supports specific interfaces - these map to FDO protocol codes
	case "eth_0":
		return 0, nil // eth interface 0
	case "eth_1":
		return 1, nil
	case "eth_2":
		return 2, nil
	case "eth_3":
		return 3, nil
	case "eth_4":
		return 4, nil
	case "eth_5":
		return 5, nil
	case "eth_6":
		return 6, nil
	case "eth_7":
		return 7, nil
	case "eth_8":
		return 8, nil
	case "eth_9":
		return 9, nil
	case "wifi_0":
		return 10, nil // wifi interface 0
	case "wifi_1":
		return 11, nil
	case "wifi_2":
		return 12, nil
	case "wifi_3":
		return 13, nil
	case "wifi_4":
		return 14, nil
	case "wifi_5":
		return 15, nil
	case "wifi_6":
		return 16, nil
	case "wifi_7":
		return 17, nil
	case "wifi_8":
		return 18, nil
	case "wifi_9":
		return 19, nil
	default:
		return 255, fmt.Errorf("unknown medium: %q", s)
	}
}
