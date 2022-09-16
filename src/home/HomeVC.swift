//
//  FirstViewController.swift
//  Pirate
//
//  Created by hyperorchid on 2020/2/15.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import UIKit
import NetworkExtension
import SwiftyJSON

extension NEVPNStatus: CustomStringConvertible {
        public var description: String {
                switch self {
                case .disconnected: return "Disconnected".locStr
                case .invalid: return "Invalid".locStr
                case .connected: return "Connected".locStr
                case .connecting: return "Connecting".locStr
                case .disconnecting: return "Disconnecting".locStr
                case .reasserting: return "Reconnecting".locStr
                @unknown default:
                        return "unknown".locStr
                }
        }
}

class HomeVC: UIViewController {
        
        @IBOutlet weak var connectButton: UIButton!
        @IBOutlet weak var vpnStatusLabel: UILabel!
        @IBOutlet weak var minersIDLabel: UILabel!
        @IBOutlet weak var minersNameLabel: UILabel!
        @IBOutlet weak var globalModelSeg: UISegmentedControl!
        @IBOutlet var nodeBackgroundView: UIView!
        
        var vpnStatusOn:Bool = false
        var targetManager:NETunnelProviderManager? = nil
        var adViews:[AdvertiseView] = []
        var timer:Timer? = nil
        var advertiseLinkSize:Int = 1
        
        override func viewDidLoad() {
                super.viewDidLoad()
                
                reloadManagers()
                
                setPoolMinersAddress()
                
                _ = RuleManager.rInst
                
                NotificationCenter.default.addObserver(self, selector: #selector(VPNStatusDidChange(_:)),
                                                       name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
                
                NotificationCenter.default.addObserver(self, selector: #selector(setMinerDetails(_:)),
                                                       name: AppConstants.NOTI_MINER_CACHE_LOADED.name, object: nil)
                
                NotificationCenter.default.addObserver(self, selector: #selector(minerChanged(_:)),
                                                       name: AppConstants.NOTI_MINER_INUSE_CHANGED.name, object: nil)
                nodeBackgroundView.layer.borderColor =  UIColor(hex: "#FF782BFF")?.cgColor//UIColor.red.cgColor//
        }
        override func viewDidAppear(_ animated: Bool) {
                super.viewDidAppear(animated)
        }
        override func viewDidDisappear(_ animated: Bool) {
                super.viewDidDisappear(animated)
                self.timer?.invalidate()
        }
        
        deinit {
                NotificationCenter.default.removeObserver(self)
        }
        override func viewWillAppear(_ animated: Bool) {
                super.viewWillAppear(animated)
                guard let addr = Wallet.WInst.Address, addr != "" else {
                        self.showCreateDialog()
                        return
                }
        }
        
        func showCreateDialog(){
                self.performSegue(withIdentifier: "CreateAccountSegID", sender: self)
        }
        
        // MARK:  UI Action
        @IBAction func startOrStop(_ sender: Any) {
                
                guard let conn = self.targetManager?.connection else{
                        reloadManagers()
                        return
                }
                
                guard conn.status == .disconnected || conn.status == .invalid else {
                        conn.stopVPNTunnel()
                        return
                }
                
                if self.targetManager?.isEnabled == false{
                        self.targetManager!.isEnabled = true
                        Task{
                                try await self.targetManager!.saveToPreferences()
                                try await self.targetManager!.loadFromPreferences()
                                startOrStop(sender)
                        }
                        return
                }
                
                guard let miner = AppSetting.coreData?.minerAddrInUsed else {
                        self.ShowTips(msg: "Choose your node first".locStr)
                        return
                }
                
                guard  Wallet.WInst.IsOpen() else{
                        
                        guard let subAddr = Wallet.WInst.SubAddress,
                              let password = AppSetting.readPassword(service: AppConstants.SERVICE_NME_FOR_OSS, account: subAddr),
                              true == Wallet.WInst.OpenWallet(auth: password) else{
                                
                                self.ShowOnePassword() {
                                        do {
                                                try self._startVPN(miner: miner)
                                        }catch let err{
                                                self.ShowTips(msg: err.localizedDescription)
                                                self.hideIndicator()
                                        }
                                }
                                
                                return
                        }
                        
                        do {
                                try self._startVPN(miner: miner)
                        }catch let err{
                                self.ShowTips(msg: err.localizedDescription)
                                self.hideIndicator()
                        }
                        return
                }
                
                do {
                        try self._startVPN(miner: miner)
                }catch let err{
                        NSLog("=======>Failed to start the VPN: \(err)")
                        self.ShowTips(msg: err.localizedDescription)
                        self.hideIndicator()
                }
        }
        
        private func _startVPN(miner:String) throws{
                
                self.showIndicator(withTitle: "VPN", and: "Starting VPN".locStr)
                
                guard let aesKey = Wallet.WInst.AesKeyWithForMiner(miner: miner) else {
                        throw AppErr.wallet("No valid key data".locStr)
                }
                let (mIP, mPort) = try Miner.prepareMiner(mid: miner)
                let options = ["AES_KEY":aesKey as NSObject,
                               "USER_SUB_ADDR":Wallet.WInst.SubAddress! as NSObject,
                               "GLOBAL_MODE":AppSetting.isGlobalModel,
                               "STREAM_MODE":AppSetting.isStreamModel,
                               "MINER_ADDR":miner as NSObject,
                               "MINER_IP":mIP as NSObject,
                               "MINER_PORT":mPort as NSObject] as? [String : NSObject]
                
                
                try self.targetManager!.connection.startVPNTunnel(options: options)
        }
        
        @objc func VPNStatusDidChange(_ notification: Notification?) {
                
                defer {
                        if self.vpnStatusOn{
                                connectButton.setBackgroundImage(UIImage.init(named: "Con_icon"), for: .normal)
                        }else{
                                connectButton.setBackgroundImage(UIImage.init(named: "Dis_butt"), for: .normal)
                        }
                }
                
                guard  let status = self.targetManager?.connection.status else{
                        return
                }
                
                NSLog("=======>VPN Status changed:[\(status.description)]")
                self.vpnStatusLabel.text = status.description
                self.vpnStatusOn = status == .connected
                if status == .invalid{
                        self.targetManager?.loadFromPreferences(){
                                err in
                                NSLog("=======>VPN loadFromPreferences [\(err?.localizedDescription  ?? "Success" )]")
                        }
                }
                
                if status == .connected || status == .disconnected{
                        self.hideIndicator()
                }
        }
        
        @IBAction func changeModel(_ sender: UISegmentedControl) {
                let old_model = AppSetting.isGlobalModel
                
                switch sender.selectedSegmentIndex{
                case 0:
                        AppSetting.isGlobalModel = false
                case 1:
                        AppSetting.isGlobalModel = true
                default:
                        AppSetting.isGlobalModel = false
                }
                
                self.notifyModelToVPN(sender:sender, oldStatus:old_model)
        }
        
        @IBAction func ShowMinerChooseView(_ sender: Any) {
                self.performSegue(withIdentifier: "ChooseMinersViewControllerSS", sender: self)
        }
        
        func setModelStatus(sender: UISegmentedControl, oldStatus:Bool){
                DispatchQueue.main.async {
                        if oldStatus{
                                sender.selectedSegmentIndex = 1
                        }else{
                                sender.selectedSegmentIndex = 0
                        }
                }
        }
        
        // MARK: - VPN Manager
        private func makeManager() -> NETunnelProviderManager {
                
                let manager = NETunnelProviderManager()
                
                manager.localizedDescription = "The Big Dipper lite".locStr
                
                let proto = NETunnelProviderProtocol()
                proto.serverAddress = "simple lite server".locStr
                proto.providerBundleIdentifier = "com.hop.simplenet.beta.extension"
                proto.disconnectOnSleep = false
                proto.providerConfiguration = [:]
                
                manager.protocolConfiguration = proto
                
                manager.isEnabled = true
                
                return manager
        }
        
        func reloadManagers() {
                
                Task { do {
                        
                        let vpnManagers = try await NETunnelProviderManager.loadAllFromPreferences()
                        if vpnManagers.count == 0{
                                self.targetManager = self.makeManager()
                                try await self.targetManager!.saveToPreferences()
                                try await self.targetManager!.loadFromPreferences()
                                return
                        }
                        self.targetManager = vpnManagers[0]
                        if self.targetManager!.isEnabled == false{
                                self.targetManager!.isEnabled = true
                        }
                        try await self.targetManager!.loadFromPreferences()
                }catch let err{
                        self.ShowTips(msg: err.localizedDescription)
                } }
                
        }

        private func getModelFromVPN(){
                guard let session = self.targetManager?.connection as? NETunnelProviderSession,
                      session.status != .invalid else{
                        NSLog("=======>Can't not load global model")
                        return
                }
                guard let message = try? JSON(["GetModel": true]).rawData() else{
                        return
                }
                try? session.sendProviderMessage(message){reponse in
                        guard let rs = reponse else{
                                return
                        }
                        let param = JSON(rs)
                        AppSetting.isGlobalModel = param["Global"].bool ?? false
                        self.setModelStatus(sender: self.globalModelSeg, oldStatus: AppSetting.isGlobalModel)
                        NSLog("=======>Curretn global model is [\(AppSetting.isGlobalModel)]")
                }
        }
        
        private func notifyModelToVPN(sender: UISegmentedControl, oldStatus:Bool){
                
                guard self.vpnStatusOn == true,
                      let session = self.targetManager?.connection as? NETunnelProviderSession,
                      session.status != .invalid else{
                        return
                }
                guard let message = try? JSON(["Global": AppSetting.isGlobalModel]).rawData() else{
                        return
                }
                do{
                        try session.sendProviderMessage(message)
                        
                }catch let err{
                        self.setModelStatus(sender: sender, oldStatus: oldStatus)
                        self.ShowTips(msg: err.localizedDescription)
                }
        }
        
        @objc func minerChanged(_ notification: Notification?) {
                if self.targetManager?.connection.status == .connected{
                        self.targetManager?.connection.stopVPNTunnel()
                }
                
                setPoolMinersAddress()
                setMinerDetails(nil)
        }
        
        private func setPoolMinersAddress(){
                DispatchQueue.main.async {
                        
                        if let minerAddr = AppSetting.coreData?.minerAddrInUsed, minerAddr != ""{
                                self.minersIDLabel.text = minerAddr
                                if let m_data = Miner.CachedMiner[minerAddr.lowercased()]{
                                        self.minersNameLabel.text = m_data.name
                                }
                        }else{
                                self.minersIDLabel.text = "Choose one miner please".locStr
                                self.minersNameLabel.text = "NAN".locStr
                        }
                }
        }
        
        
        @objc func setMinerDetails(_ notification: Notification?){DispatchQueue.main.async {
                guard let minerAddr = AppSetting.coreData?.minerAddrInUsed, minerAddr != "" else{
                        self.minersIDLabel.text = "Choose one miner please".locStr
                        self.minersNameLabel.text = "NAN".locStr
                        return
                }
                if let m_data = Miner.CachedMiner[minerAddr.lowercased()]{
                        self.minersNameLabel.text = m_data.name
                }
        }}
}
