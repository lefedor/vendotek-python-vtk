# -*- coding: utf-8 -*-

"""
Пайтон3-Библиотека клиента Vendotek Ethernet/Serial/RS232 по VTK протоколу
Vendotek VTK over Ethernet/Serial/RS232 client python3 library class. 
(c) FedorFL F Lejepekov
ffl.public@gmail.com
+79219869856

"""


import traceback
import logging
logger = logging.getLogger(__name__)

import string
import random

from pprint import pprint

import socket
import sys

from datetime import datetime

import time

from ber_tlv.tlv import *


#-----------------------------------------------------------------------
#-----------------------------------------------------------------------


class wVTK:

	wTest = False
	#wDbg = False
	wDbg = True
	
	wMode = 'Ethernet' #Ethernet / Serial
	
	wHost = None
	wPort = None
	
	wVmcId = b'\x96\xFB'
	wPosId = b'\x97\xFB'
	
	wSckClient = None
	
	wTimeout = 6.0
	
	wFlushData = None
	
	wLastVRP = None
	wLastCDP = None
	wLastMFR = None
	
	wLastLocalTime = None
	
	wEventName = None
	wEventNumber = None
	
	wQRToDisplay = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
		
	def __init__(self, wHost, wPort, wTest=None, wDbg=None):
		
		self.wHost = wHost
		self.wPort = wPort
		
		if wTest:
			self.wTest = wTest
		
		if wDbg:
			self.wDbg = wDbg
			
		try:
			self.wSckClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error:
			print('Failed to create socket')
			sys.exit()
			
		self.wConnect()
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSetHost(self, wHost):
		
		self.wHost = wHost
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSetPort(self, wPort):
		
		self.wPort = wPort
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wConnect(self):
		
		self.wSckClient.connect((self.wHost, self.wPort))
		
		self.wSckClient.settimeout(self.wTimeout)
		
		#------
		
		if self.wDbg:
			print('Socket Connected to ' + self.wHost )
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wDisconnect(self):
		
		self.wSckClient.shutdown(socket.SHUT_RDWR)
		self.wSckClient.close()
		
		#------
		
		if self.wDbg:
			print('Socket Disconnected from ' + self.wHost )
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wBuildMsg(self, wPayload):
		
		wMsg = Tlv.build(wPayload)
		
		wMsg = self.wVmcId + wMsg
		
		wLen = len(wMsg)
		wLen = wLen.to_bytes(2, 'big')
		
		wMsg = wLen+wMsg
		
		return wMsg
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wParseMsg(self, wRxMsg):
		
		wPayloadDict = {}
		
		wResult = None
		
		if False and self.wDbg:
			print('wRxMsg')
			print(wRxMsg)
		
		wLen = wRxMsg[0:2]
		
		wId = wRxMsg[2:4]
		
		wPayload = wRxMsg[4:]
		
		#------
		
		if False and self.wDbg:
			print('wPayload')
			print(wPayload)
			pprint(Tlv.parse(wPayload))
		
		#------
		
		if wId == self.wPosId:
			
			wPayload = Tlv.parse(wPayload)
			#pprint(wPayload)
			
			#------
			
			if wPayload and isinstance(wPayload, list):
				
				wLocalEventName = None
				wLocalEventNum = None
				
				for wPiece in wPayload:
					wPayloadDict[wPiece[0]] = wPiece[1].decode()
					
					#if wPiece[0] == 1:#0x1  Message name
						#wPayloadDict[wPiece[0]] = wPayloadDict[wPiece[0]].decode()
					
					# 0x3  Operation number
					# 0x6  Operation timeout, sec
					# 0x8  Event number
					if wPiece[0] == 0x3 \
						or wPiece[0] == 0x6 \
						or wPiece[0] == 0x8: 
						
						wPayloadDict[wPiece[0]] = int(wPayloadDict[wPiece[0]])
						
						if wPiece[0] == 0x08:
							wLocalEventNum = wPayloadDict[wPiece[0]]
						
					elif wPiece[0] == 0x4:
						
						wPayloadDict[wPiece[0]] = float(wPayloadDict[wPiece[0]])
					
					elif wPiece[0] == 0x13:	
						
						#3.19. Banking receipt
						wPayloadDict[wPiece[0]] = wPiece[1].decode()
					
					elif wPiece[0] == 0x11:	
					
						if self.wDbg:
							print('Got NEW LocalTime')
							print(wRxMsg)
						
						#wTimePiece = wCurrDT.strftime("%Y%m%dT%H%M+0300")
						
						self.wLastLocalTime = wPiece[1].decode()
						
						if int(self.wLastLocalTime[:1]) != 1:
							
							self.wLastLocalTime = None
							
						else:
							
							"""
								If a POS sends a local time, in which the first byte is not equal to “2”, a VMC must insert
								the actual local time to all messages during some transmission interval. The required local time
								accuracy is determined outside the scope of this documen
							"""
							
							pass
							
					elif wPiece[0] == 0x07:
						
						"""
						CSAPP Cash Sale Approved
						CSDEN Cash Sale Denied
						"""
						
						wPayloadDict[wPiece[0]] = wPiece[1].decode()
						wLocalEventName = wPayloadDict[wPiece[0]]
				
				wPayloadDict[0] = 'wSuccess'
				
				if wLocalEventName:
					
					if self.wDbg:
						print('Got NEW wLocalEventName')
						print(wRxMsg)
					
					self.wEventName = wLocalEventName
					self.wEventNumber = wLocalEventNum
				
				#------
				
				if self.wDbg:
					
					print('wPayloadDict')
					pprint(wPayloadDict)
				
				return wPayloadDict
		
		#------
		
		return {0, 'wError'}
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wFlushReset(self):
		
		self.wFlushData = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wVrpReset(self):
		
		self.wLastVRP = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wCdpReset(self):
		
		self.wLastCDP = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wMfrReset(self):
		
		self.wLastMFR = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wLocalTimeReset(self):
		
		self.wLastLocalTime = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wEventReset(self):
		
		self.wEventName = None
		self.wEventNumber = None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wFlush(self, wLocalTimeout = 2.0):
		
		if self.wDbg:
			print('FLUSH IN')
		
		self.wSckClient.settimeout(wLocalTimeout)
		
		try:
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload FLUSH')
				pprint(wRxPayload)
			
			#------
			
			if wRxPayload and wRxPayload[0] == 'wSuccess':
				
				self.wFlushData = wRxPayload
				
				#if mifare
				if wRxPayload[0x01] == 'MFR':
					
					wLastMFR = wRxPayload
					
					if self.wDbg:
						print('FLUSH: Mifare card red')
						pprint(wRxPayload)
				
				#if CDP
				elif wRxPayload[0x01] == 'CDP':
					
					wLastCDP = wRxPayload
					
					if self.wDbg:
						print('FLUSH: wRxPayload CDP Is payed')
						pprint(wRxPayload)
				
				#if VRP
				elif wRxPayload[0x01] == 'VRP' and wRxPayload[4] > 0.01:
					
					self.wLastVRP = wRxPayload
					
					if self.wDbg:
						print('FLUSH: wRxPayload VRP Is payed')
						pprint(wRxPayload)
				else:
					
					print('FLUSH: wRxPayload unexpected: ' + str(wRxPayload[0x01]))
					pprint(wRxPayload)
					
					
				
		except socket.timeout:
			
			if self.wDbg:
				print('No data on flush (timeout)')
		
		self.wSckClient.settimeout(self.wTimeout)
		
		return None
		
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSendDis(self, wTimeout=60, wWithFlush=False):
		
		if wWithFlush:
			
			self.wFlush()
		
		wPayload = {0x01: b'DIS'}
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
		
		wMsg = self.wBuildMsg(wPayload = wPayload)
		
		#try:
		#	#Flush It
		#	wResponce = self.wSckClient.recv(1024)
		#except:
		#	pass
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload DIS')
				pprint(wRxPayload)
				
			return wRxPayload
			
		except socket.error:
			print('Failed to send DIS data')
			
		return None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSendIdl(self, wTimeout=None, wKeepAlive=None, wQrCode=None, wSendLocalTime=False, wWithFlush=False):
		
		if wWithFlush:
			
			self.wFlush()
		
		wPayload = {0x01: b'IDL'}
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
		
		if wKeepAlive:
			wPayload[0x05] = bytes(str(wKeepAlive).encode('ASCII'))
		
		if wQrCode:
			wPayload[0x0A] = bytes(str(wQrCode).encode('ASCII'))
			
		if wSendLocalTime or self.wLastLocalTime:
			
			wCurrDT = datetime.now()
			wTimePiece = wCurrDT.strftime("%Y%m%dT%H%M+0300")
			
			wPayload[0x011] = bytes(str(wTimePiece).encode('ASCII'))
			
			self.wLocalTimeReset()
		
		wMsg = self.wBuildMsg(wPayload = wPayload)
		
		#try:
		#	#Flush It
		#	wResponce = self.wSckClient.recv(1024)
		#except:
		#	pass
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload IDL')
				pprint(wRxPayload)
				
			return wRxPayload
			
		except socket.error:
			print('Failed to send IDL data')
			
		return None
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSendAbr(self, wTimeout=60):
		
		wPayload = {0x01: b'ABR'}
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
		
		wMsg = self.wBuildMsg(wPayload = wPayload)
		
		#try:
		#	#Flush It
		#	wResponce = self.wSckClient.recv(1024)
		#except:
		#	pass
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload ABR')
				pprint(wRxPayload)
				
			return wRxPayload
			
		except socket.error:
			print('Failed to send ABR data')
			
		return None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSendFin(self, wTimeout=None, wQrCode=None):
		
		wPayload = {0x01: b'FIN'}
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
		
		if wQrCode:
			wPayload[0x0A] = bytes(str(wQrCode).encode('ASCII'))
		
		wMsg = self.wBuildMsg(wPayload = wPayload)
		
		#try:
		#	#Flush It
		#	wResponce = self.wSckClient.recv(1024)
		#except:
		#	pass
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload FIN')
				pprint(wRxPayload)
				
			return wRxPayload
			
		except socket.error:
			print('Failed to send FIN data')
			
		return None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wSendSta(self, wAmount = None, wTimeout=60):
		
		wPayload = {0x01: b'STA'}
		
		if wAmount:
			wPayload[0x04] = bytes(str(wPrice).encode('ASCII'))
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
		
		wMsg = self.wBuildMsg(wPayload = wPayload)
		
		#try:
		#	#Flush It
		#	wResponce = self.wSckClient.recv(1024)
		#except:
		#	pass
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload STA')
				pprint(wRxPayload)
				
			return wRxPayload
			
		except socket.error:
			print('Failed to send STA data')
			
		return None
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wPing(self, wTimeout=None):
		
		return self.wSendIdl()
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wPayReq(self, wPrice, wProdId=None, wProdName=None, wTimeout=None):
		
		#IDL Init stage	
		
		self.wFlush()
		
		#wPayload = {0x01: b'IDL', 0x04: wPrice.to_bytes(4, 'big'), }
		wPayload = {0x01: b'IDL', 0x04: bytes(str(wPrice).encode('ASCII')), }
		
		if wProdId:
			wPayload[0x09] = bytes(str(wProdId).encode('ASCII'))
		
		if wProdName:
			wPayload[0x0F] = bytes(str(wProdName).encode('ASCII'))
		
		if wTimeout:
			wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
			
		
		#------
		
		wMsg = self.wBuildMsg(wPayload)
		#pprint(wMsg)
		
		#------
		
		wOperationNext = None
			
		try:
			self.wSckClient.send(wMsg)
			
			time.sleep(1)
			
			wResponce = self.wSckClient.recv(1024)
			
			wRxPayload = self.wParseMsg(wRxMsg = wResponce)
			
			if self.wDbg:
				print('wRxPayload PayReq')
				pprint(wRxPayload)
				
			if wRxPayload and wRxPayload[0] == 'wSuccess':
				
				#VRP Stage
				
				wOperationNext = wRxPayload[0x03]+1
				if not wTimeout:
					
					wTimeout = wRxPayload[0x06]
				
		except socket.error:
			print('Failed to send IDL INIT data')
		
		#------
		
		if wOperationNext:
			
			try:

				wPayload = {0x01: b'VRP', 0x03: bytes(str(wOperationNext).encode('ASCII')),  0x04: bytes(str(wPrice).encode('ASCII')), }

				if wProdId:
					wPayload[0x09] = bytes(str(wProdId).encode('ASCII'))
				
				if wProdName:
					wPayload[0x0F] = bytes(str(wProdName).encode('ASCII'))
		
				if wTimeout:
					wPayload[0x06] = bytes(str(wTimeout).encode('ASCII'))
				
				#pprint(wPayload)
				
				#------
				
				wMsg = self.wBuildMsg(wPayload)
				
				self.wSckClient.settimeout(float(wTimeout)+2.0)
				
				if self.wDbg:
					print('wTxPayload VRP')
					pprint(wPayload)
				
				self.wSckClient.send(wMsg)
				
				#------
				
				time.sleep(1)
				
				wResponce = self.wSckClient.recv(1024)
				
				wRxPayload = self.wParseMsg(wRxMsg = wResponce)
				
				if self.wDbg:
					print('wRxPayload VRP')
					pprint(wRxPayload)
				
				#------
				
				if wRxPayload and wRxPayload[0] == 'wSuccess' and wRxPayload[4] > 0.01:
					
					if self.wDbg:
						print('wRxPayload VRP Is payed')
						pprint(wRxPayload)
					
					self.wLastVRP = wRxPayload
					
					wResult = wRxPayload[4]
					
				else:
					
					if self.wDbg:
						print('wRxPayload VRP Not payed')
						pprint(wRxPayload)
					
					wResult = False
					
			except socket.error:
				print('Failed to send VRP data')
			
			#IDL fin stage
		
		#------
		
		self.wSckClient.settimeout(self.wTimeout)
		
		#------
		
		self.wPing()
		
		#------
		
		return wResult
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def wQRDisplay(self, wQrCode):
		
		return self.wSendIdl(wQrCode=wQrCode)
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
	
	def crc16(data: bytes):
		'''
		CRC-16 (CCITT) implemented with a precomputed lookup table
		'''
		table = [ 
			0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
			0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
			0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
			0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
			0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
			0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
			0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
			0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
			0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
			0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
			0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
			0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
			0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
			0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
			0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
			0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
		]
		
		crc = 0xFFFF
		for byte in data:
			crc = (crc << 8) ^ table[(crc >> 8) ^ byte]
			crc &= 0xFFFF                                   # important, crc must stay 16bits all the way through
		return crc
	
	
	#-----------------------------------------------------------------------
	#-----------------------------------------------------------------------
	
		
wVTKInst = wVTK('192.168.0.209', 62801)

#wVTKInst.wPing()
#wVTKInst.wSendIdl(wSendLocalTime = True)
wVTKInst.wPayReq(5000, wProdName='PROG4')


"""

"""

