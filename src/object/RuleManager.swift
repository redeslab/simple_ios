//
//  RuleManager.swift
//  extension
//
//  Created by wesley on 2022/7/14.
//  Copyright © 2022 hyperorchid. All rights reserved.
//

import Foundation
import CoreData
import Simple
import SwiftyJSON

class RuleManager:NSObject{
        
        private var coreData:CDRuleVersion?
        public static var rInst = RuleManager()
        
        override init() {
                super.init()
                let context = DataShareManager.privateQueueContext()
                
                var rVer = NSManagedObject.findOneEntity(AppConstants.DBNAME_RuleVer,
                                                         context: context) as? CDRuleVersion
                if rVer == nil{
                        rVer = CDRuleVersion(context: context)
                        rVer!.dnsVer = -1
                        rVer!.ipVer = -1
                        rVer!.mustVer = -1
                        rVer!.dnsStr = loadTxtStr("rule")
                        rVer!.ipStr = loadTxtStr("bypass2")
                        rVer!.mustStr = loadTxtStr("must_hit")
                        DataShareManager.saveContext(context)
                }
                
                self.coreData = rVer
                DispatchQueue.global().async {
                        
                        var err:NSError?
                        guard let verJson =  SimpleRuleVerInt(&err), err == nil else{
                                NSLog("------>>>load rule version err:\(err?.localizedDescription ?? "no err")")
                                return
                        }
                        
                        let jsonVer = JSON(verJson)
                        let dns_ver = jsonVer["dns"].int32 ?? -1
                        let ip_ver = jsonVer["by_pass"].int32 ?? -1
                        let must_ver = jsonVer["must_hit"].int32 ?? -1
                        var needSave = false
                        if dns_ver > rVer!.dnsVer{
                                let dnsStr = SimpleRuleDataLoad(&err)
                                if err == nil{
                                        rVer?.dnsStr = dnsStr
                                        rVer?.dnsVer = dns_ver
                                        needSave = true
                                }else{
                                        NSLog("------>>> load dns rule failed:\(err!.localizedDescription)")
                                }
                        }
                        
                        if ip_ver > rVer!.ipVer{
                                let ipStr = SimpleByPassDataLoad(&err)
                                if err == nil{
                                        rVer?.ipStr = ipStr
                                        rVer?.ipVer = ip_ver
                                        needSave = true
                                }else{
                                        NSLog("------>>> load ip rule failed:\(err!.localizedDescription)")
                                }
                        }
                        
                        if must_ver > rVer!.mustVer{
                                let mustStr = SimpleMustHitData(&err)
                                if err == nil{
                                        rVer?.mustStr = mustStr
                                        rVer?.mustVer = must_ver
                                        needSave = true
                                }else{
                                        NSLog("------>>> load must hit failed:\(err!.localizedDescription)")
                                }
                        }
                        
                        if needSave{
                                DataShareManager.saveContext(context)
                                self.coreData = rVer
                                NSLog("------>>> rule version changed......")
                        }
                }
        }
        
        private func loadTxtStr(_ name:String)->String{
                guard let filepath = Bundle.main.path(forResource: name, ofType: "txt") else{
                        NSLog("------>>>failed to find \(name) text path")
                        return ""
                }
                guard let contents = try? String(contentsOfFile: filepath) else{
                        NSLog("------>>>failed to read  \(name) txt")
                        return ""
                }
                //                NSLog("------>>>rule contents:\(contents)")
                return contents
        }
}
