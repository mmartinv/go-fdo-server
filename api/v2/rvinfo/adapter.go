// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package rvinfo

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"

	"github.com/fido-device-onboard/go-fdo-server/api/v2/components"
	"github.com/fido-device-onboard/go-fdo-server/internal/utils"
)

// RVInfoToProtocol converts V2 API RVInfo (nested instructions) to protocol format
//
// Expected V2 format (array of arrays of single-key objects):
//
//	[
//	  [
//	    {"dns": "rendezvous.example.com"},
//	    {"protocol": "http"},
//	    {"owner_port": 8080}
//	  ],
//	  [
//	    {"ip": "192.168.1.100"},
//	    {"protocol": "https"},
//	    {"owner_port": 8443}
//	  ]
//	]
//
// Each outer array element is an RV directive (fallback options).
// Each inner array element is a single instruction (key-value pair).
func RVInfoToProtocol(rvInfo components.RVInfo) ([][]protocol.RvInstruction, error) {
	out := make([][]protocol.RvInstruction, 0, len(rvInfo))

	for directiveIdx, instructions := range rvInfo {
		group := make([]protocol.RvInstruction, 0, len(instructions))
		hasDNSorIP := false

		for instrIdx, instruction := range instructions {
			// Each instruction in V2 is represented as RVInstruction_Item union type
			// We need to try to unmarshal it as each possible type to determine what it is

			// Try DNS
			if dns, err := instruction.AsDNS(); err == nil && dns.Dns != nil {
				enc, err := cbor.Marshal(*dns.Dns)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode dns: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVDns, Value: enc})
				hasDNSorIP = true
				continue
			}

			// Try IP
			if ipInstr, err := instruction.AsIP(); err == nil && ipInstr.Ip != nil {
				ip := net.ParseIP(*ipInstr.Ip)
				if ip == nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: invalid ip %q", directiveIdx, instrIdx, *ipInstr.Ip)
				}
				enc, err := cbor.Marshal(ip)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode ip: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: enc})
				hasDNSorIP = true
				continue
			}

			// Try Protocol
			if protoInstr, err := instruction.AsProtocol(); err == nil && protoInstr.Protocol != nil {
				code, err := utils.RVProtocolFromString(string(*protoInstr.Protocol))
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: %w", directiveIdx, instrIdx, err)
				}
				enc, err := cbor.Marshal(code)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode protocol: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVProtocol, Value: enc})
				continue
			}

			// Try Medium
			if mediumInstr, err := instruction.AsMedium(); err == nil && mediumInstr.Medium != nil {
				code, err := utils.RVMediumFromString(string(*mediumInstr.Medium))
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: %w", directiveIdx, instrIdx, err)
				}
				enc, err := cbor.Marshal(code)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode medium: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVMedium, Value: enc})
				continue
			}

			// Try DevicePort
			if portInstr, err := instruction.AsDevicePort(); err == nil && portInstr.DevicePort != nil {
				port := validatePortNumber(*portInstr.DevicePort)
				if port == 0 {
					return nil, fmt.Errorf("rvinfo[%d][%d]: invalid device_port %d", directiveIdx, instrIdx, *portInstr.DevicePort)
				}
				enc, err := cbor.Marshal(uint16(port))
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode device_port: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVDevPort, Value: enc})
				continue
			}

			// Try OwnerPort
			if portInstr, err := instruction.AsOwnerPort(); err == nil && portInstr.OwnerPort != nil {
				port := validatePortNumber(*portInstr.OwnerPort)
				if port == 0 {
					return nil, fmt.Errorf("rvinfo[%d][%d]: invalid owner_port %d", directiveIdx, instrIdx, *portInstr.OwnerPort)
				}
				enc, err := cbor.Marshal(uint16(port))
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode owner_port: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVOwnerPort, Value: enc})
				continue
			}

			// Try WifiSSID
			if ssidInstr, err := instruction.AsWifiSSID(); err == nil && ssidInstr.WifiSsid != nil {
				enc, err := cbor.Marshal(*ssidInstr.WifiSsid)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode wifi_ssid: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVWifiSsid, Value: enc})
				continue
			}

			// Try WifiPW
			if pwInstr, err := instruction.AsWifiPW(); err == nil && pwInstr.WifiPw != nil {
				enc, err := cbor.Marshal(*pwInstr.WifiPw)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode wifi_pw: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVWifiPw, Value: enc})
				continue
			}

			// Try DevOnly
			if devOnlyInstr, err := instruction.AsDevOnly(); err == nil && devOnlyInstr.DevOnly != nil && *devOnlyInstr.DevOnly {
				group = append(group, protocol.RvInstruction{Variable: protocol.RVDevOnly})
				continue
			}

			// Try OwnerOnly
			if ownerOnlyInstr, err := instruction.AsOwnerOnly(); err == nil && ownerOnlyInstr.OwnerOnly != nil && *ownerOnlyInstr.OwnerOnly {
				group = append(group, protocol.RvInstruction{Variable: protocol.RVOwnerOnly})
				continue
			}

			// Try RVBypass
			if bypassInstr, err := instruction.AsRVBypass(); err == nil && bypassInstr.RvBypass != nil && *bypassInstr.RvBypass {
				group = append(group, protocol.RvInstruction{Variable: protocol.RVBypass})
				continue
			}

			// Try DelaySeconds
			if delayInstr, err := instruction.AsDelaySeconds(); err == nil && delayInstr.DelaySeconds != nil {
				if *delayInstr.DelaySeconds < 0 {
					return nil, fmt.Errorf("rvinfo[%d][%d]: delay_seconds must be non-negative", directiveIdx, instrIdx)
				}
				secs := uint32(*delayInstr.DelaySeconds)
				enc, err := cbor.Marshal(secs)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode delay_seconds: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVDelaysec, Value: enc})
				continue
			}

			// Try SvCertHash
			if hashInstr, err := instruction.AsSvCertHash(); err == nil && hashInstr.SvCertHash != nil {
				hash, err := hex.DecodeString(*hashInstr.SvCertHash)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: sv_cert_hash: %w", directiveIdx, instrIdx, err)
				}
				enc, err := cbor.Marshal(hash)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode sv_cert_hash: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVSvCertHash, Value: enc})
				continue
			}

			// Try ClCertHash
			if hashInstr, err := instruction.AsClCertHash(); err == nil && hashInstr.ClCertHash != nil {
				hash, err := hex.DecodeString(*hashInstr.ClCertHash)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: cl_cert_hash: %w", directiveIdx, instrIdx, err)
				}
				enc, err := cbor.Marshal(hash)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode cl_cert_hash: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVClCertHash, Value: enc})
				continue
			}

			// Try UserInput (FDO spec defines RVUserInput as Boolean)
			if userInputInstr, err := instruction.AsUserInput(); err == nil && userInputInstr.UserInput != nil && *userInputInstr.UserInput {
				enc, err := cbor.Marshal(true)
				if err != nil {
					return nil, fmt.Errorf("directive[%d]: user_input: %w", directiveIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVUserInput, Value: enc})
				continue
			}

			// Try ExtRV
			if extrvInstr, err := instruction.AsExtRV(); err == nil && extrvInstr.ExtRv != nil {
				enc, err := cbor.Marshal(*extrvInstr.ExtRv)
				if err != nil {
					return nil, fmt.Errorf("rvinfo[%d][%d]: failed to encode ext_rv: %w", directiveIdx, instrIdx, err)
				}
				group = append(group, protocol.RvInstruction{Variable: protocol.RVExtRV, Value: enc})
				continue
			}

			// If we get here, we couldn't parse the instruction
			return nil, fmt.Errorf("rvinfo[%d][%d]: unknown or invalid instruction type", directiveIdx, instrIdx)
		}

		// Spec requires at least one of DNS or IP to be present for an RV entry
		if !hasDNSorIP {
			return nil, fmt.Errorf("rvinfo[%d]: at least one of dns or ip must be specified", directiveIdx)
		}

		out = append(out, group)
	}

	return out, nil
}

// RVInfoFromProtocol converts protocol format back to V2 API RVInfo (nested instructions)
//
// Output format (array of arrays of single-key objects):
// [[{"dns":"host"},{"protocol":"http"},{"owner_port":8080}]]
func RVInfoFromProtocol(proto [][]protocol.RvInstruction) (components.RVInfo, error) {
	out := make(components.RVInfo, 0, len(proto))

	for _, directive := range proto {
		group := make(components.RVInstruction, 0, len(directive))

		for _, instr := range directive {
			var item components.RVInstruction_Item

			switch instr.Variable {
			case protocol.RVDns:
				var dns string
				if err := cbor.Unmarshal(instr.Value, &dns); err != nil {
					return nil, fmt.Errorf("failed to unmarshal dns: %w", err)
				}
				if err := item.FromDNS(components.DNS{Dns: &dns}); err != nil {
					return nil, err
				}

			case protocol.RVIPAddress:
				var ip net.IP
				if err := cbor.Unmarshal(instr.Value, &ip); err != nil {
					return nil, fmt.Errorf("failed to unmarshal ip: %w", err)
				}
				ipStr := ip.String()
				if err := item.FromIP(components.IP{Ip: &ipStr}); err != nil {
					return nil, err
				}

			case protocol.RVProtocol:
				var code uint8
				if err := cbor.Unmarshal(instr.Value, &code); err != nil {
					return nil, fmt.Errorf("failed to unmarshal protocol: %w", err)
				}
				protoStr, err := utils.RVProtocolToString(code)
				if err != nil {
					return nil, err
				}
				protoType := components.RVProtocol(protoStr)
				if err := item.FromProtocol(components.Protocol{Protocol: &protoType}); err != nil {
					return nil, err
				}

			case protocol.RVMedium:
				var code uint8
				if err := cbor.Unmarshal(instr.Value, &code); err != nil {
					return nil, fmt.Errorf("failed to unmarshal medium: %w", err)
				}
				mediumStr, err := utils.RVMediumToString(code)
				if err != nil {
					return nil, err
				}
				mediumType := components.MediumMedium(mediumStr)
				if err := item.FromMedium(components.Medium{Medium: &mediumType}); err != nil {
					return nil, err
				}

			case protocol.RVDevPort:
				var port uint16
				if err := cbor.Unmarshal(instr.Value, &port); err != nil {
					return nil, fmt.Errorf("failed to unmarshal device_port: %w", err)
				}
				portNum := int(port)
				if err := item.FromDevicePort(components.DevicePort{DevicePort: &portNum}); err != nil {
					return nil, err
				}

			case protocol.RVOwnerPort:
				var port uint16
				if err := cbor.Unmarshal(instr.Value, &port); err != nil {
					return nil, fmt.Errorf("failed to unmarshal owner_port: %w", err)
				}
				portNum := int(port)
				if err := item.FromOwnerPort(components.OwnerPort{OwnerPort: &portNum}); err != nil {
					return nil, err
				}

			case protocol.RVWifiSsid:
				var ssid string
				if err := cbor.Unmarshal(instr.Value, &ssid); err != nil {
					return nil, fmt.Errorf("failed to unmarshal wifi_ssid: %w", err)
				}
				if err := item.FromWifiSSID(components.WifiSSID{WifiSsid: &ssid}); err != nil {
					return nil, err
				}

			case protocol.RVWifiPw:
				var pw string
				if err := cbor.Unmarshal(instr.Value, &pw); err != nil {
					return nil, fmt.Errorf("failed to unmarshal wifi_pw: %w", err)
				}
				if err := item.FromWifiPW(components.WifiPW{WifiPw: &pw}); err != nil {
					return nil, err
				}

			case protocol.RVDevOnly:
				devOnly := true
				if err := item.FromDevOnly(components.DevOnly{DevOnly: &devOnly}); err != nil {
					return nil, err
				}

			case protocol.RVOwnerOnly:
				ownerOnly := true
				if err := item.FromOwnerOnly(components.OwnerOnly{OwnerOnly: &ownerOnly}); err != nil {
					return nil, err
				}

			case protocol.RVBypass:
				rvBypass := true
				if err := item.FromRVBypass(components.RVBypass{RvBypass: &rvBypass}); err != nil {
					return nil, err
				}

			case protocol.RVDelaysec:
				var secs uint32
				if err := cbor.Unmarshal(instr.Value, &secs); err != nil {
					return nil, fmt.Errorf("failed to unmarshal delay_seconds: %w", err)
				}
				if secs > math.MaxInt32 {
					return nil, fmt.Errorf("delay_seconds value %d overflows int32", secs)
				}
				secsInt := int32(secs)
				if err := item.FromDelaySeconds(components.DelaySeconds{DelaySeconds: &secsInt}); err != nil {
					return nil, err
				}

			case protocol.RVSvCertHash:
				var hash []byte
				if err := cbor.Unmarshal(instr.Value, &hash); err != nil {
					return nil, fmt.Errorf("failed to unmarshal sv_cert_hash: %w", err)
				}
				hashStr := hex.EncodeToString(hash)
				if err := item.FromSvCertHash(components.SvCertHash{SvCertHash: &hashStr}); err != nil {
					return nil, err
				}

			case protocol.RVClCertHash:
				var hash []byte
				if err := cbor.Unmarshal(instr.Value, &hash); err != nil {
					return nil, fmt.Errorf("failed to unmarshal cl_cert_hash: %w", err)
				}
				hashStr := hex.EncodeToString(hash)
				if err := item.FromClCertHash(components.ClCertHash{ClCertHash: &hashStr}); err != nil {
					return nil, err
				}

			case protocol.RVUserInput:
				userInput := true
				if err := item.FromUserInput(components.UserInput{UserInput: &userInput}); err != nil {
					return nil, err
				}

			case protocol.RVExtRV:
				var extrv []string
				if err := cbor.Unmarshal(instr.Value, &extrv); err != nil {
					return nil, fmt.Errorf("failed to unmarshal ext_rv: %w", err)
				}
				if err := item.FromExtRV(components.ExtRV{ExtRv: &extrv}); err != nil {
					return nil, err
				}

			default:
				slog.Warn("Skipping unknown RV instruction variable", "variable", instr.Variable)
				continue
			}

			group = append(group, item)
		}

		out = append(out, group)
	}

	return out, nil
}

// validatePortNumber validates that a port number is in valid range (1-65535)
func validatePortNumber(port int) int {
	if port < 1 || port > 65535 {
		return 0
	}
	return port
}
