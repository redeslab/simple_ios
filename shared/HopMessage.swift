//
//  HopMessage.swift
//  Pirate
//
//  Created by hyperorchid on 2020/3/4.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import Foundation
import NEKit

public class HopMessage:NSObject{
        public static let MAX_BUFFER_SIZE = Opt.MAXNWTCPSocketReadDataSize - 1
        static let SetupSynFormat = "{\"IV\":%@,\"SubAddr\":\"%@\"}"
        public static func SetupMsg(iv:Data,
                                    subAddr:String)throws -> Data{
                guard let iv_data = try? JSONSerialization.data(withJSONObject: iv.bytes, options: []) else{
                        throw HopError.msg("iv data to json err:")
                }
                
                guard let iv_str = String(data:iv_data, encoding: .utf8) else{
                        throw HopError.msg("iv json data to string failed")
                }
                
                let syn = String(format: SetupSynFormat, iv_str, subAddr)
                
                return syn.data(using: .utf8)!
        }
        
        static let ProbFormat = "{\"Target\":\"%@\",\"MaxPacketSize\":\(HopMessage.MAX_BUFFER_SIZE)}"
        public static func ProbMsg(target:String) throws -> Data{
                let req =  String(format: ProbFormat, target)
                return req.data(using: .utf8)!
        }
        
        public static  func generateRandomBytes(size:Int) -> Data? {

            var keyData = Data(count: size)
            let result = keyData.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
            }
            if result == errSecSuccess {
                return keyData
            } else {
                return nil
            }
        }
}
