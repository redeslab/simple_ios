//
//  Wallet.swift
//  Pirate
//
//  Created by wesley on 2020/9/19.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import Foundation
import CoreData
import Simple
import SwiftyJSON
import CryptoSwift

class Wallet:NSObject{
        
        var Address:String?
        var SubAddress:String?
        var coreData:CDWallet?
        
        public static var WInst = Wallet()
        
        override init() {
                super.init()
                guard let core_data = NSManagedObject.findOneEntity(AppConstants.DBNAME_WALLET,
                                                              context: DataShareManager.privateQueueContext()) as? CDWallet else{
                                return
                }
                
                guard let jsonStr = core_data.walletJSON, jsonStr != "" else {
                        return
                }
                
                guard SimpleLoadWallet(jsonStr) else {
                        NSLog("=======>[Wallet init] parse json failed[\(jsonStr)]")
                        return
                }

                self.Address = core_data.address
                self.SubAddress = core_data.subAddress
                coreData = core_data
        }
        
        public func initByJson(_ jsonData:Data){
                let jsonObj = JSON(jsonData)
                self.Address = jsonObj["mainAddress"].string
                self.SubAddress = jsonObj["subAddress"].string
        }
        
        public static func NewInst(auth:String) -> Bool{
                guard let jsonData = SimpleNewWallet(auth) else{
                        return false
                }
                populateWallet(data: jsonData)
                
                return true
        }
        
        private static func populateWallet(data:Data){
                WInst.initByJson(data)
                
                let context = DataShareManager.privateQueueContext()
                var core_data = NSManagedObject.findOneEntity(AppConstants.DBNAME_WALLET,
                                                              context: context) as? CDWallet
                if core_data == nil{
                        core_data = CDWallet(context: context)
                }
                
                core_data!.walletJSON = String(data: data, encoding: .utf8)
                core_data!.address = WInst.Address
                core_data!.subAddress = WInst.SubAddress
                WInst.coreData = core_data
                DataShareManager.saveContext(context)
        }
        
        public static func ImportWallet(auth:String, josn:String) -> Bool{
                guard SimpleImportWallet(josn, auth) else {
                        return false
                }
                populateWallet(data: Data(josn.utf8))
                
                return true
        }
        
        public func IsOpen() -> Bool{
                return SimpleIsOpen()
        }
        
        public func OpenWallet(auth:String) -> Bool{
                return SimpleOpenWallet(auth)
        }
        
        public func MainPrikey() -> Data?{
                return SimplePriKeyData()
        }
        
        public func SubPrikey() -> Data?{
                return SimpleSubPriKeyData()
        }
        
        public func AesKeyWithForMiner(miner:String)->String?{
                return SimpleAesKeyBase64ForMiner(miner)
        }
}
