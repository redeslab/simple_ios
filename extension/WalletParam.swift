//
//  Protocol.swift
//  extension
//
//  Created by hyperorchid on 2020/3/3.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import Foundation
import SwiftyJSON
import CoreData

public class WalletParam:NSObject{
        public static var pInst = WalletParam()
        public var selfAddr:String!
        public var minerAddress:String!
        public var minerNetAddr:String!
        
        public var aesKey:String!
        public var lastMsg:Data!
        var isDebug:Bool = true
        
        var ruleCoreData:CDRuleVersion!
        
        public override init() {
                super.init()
        }
        
        public func setup(param:[String : NSObject]) throws{
                
                self.isDebug            = param["IS_TEST"] as? Bool ?? true
                self.minerAddress       = (param["MINER_ADDR"] as! String)
                self.selfAddr     = (param["USER_SUB_ADDR"] as! String)
                self.aesKey             = param["AES_KEY"] as? String
                
                let ip         = (param["MINER_IP"] as! String)
                let port            = (param["MINER_PORT"] as! Int)
                
                self.minerNetAddr = String(format: "%@:%d", ip, port)
                
                let context = DataShareManager.privateQueueContext()
                
                let rVer = NSManagedObject.findOneEntity(AppConstants.DBNAME_RuleVer,
                                                         context: context) as? CDRuleVersion
                if rVer == nil{
                        throw AppErr.rule("no valid dns or ip rules")
                }
                
                self.ruleCoreData = rVer!
        }
}
