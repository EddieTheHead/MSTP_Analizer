# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

#  Copyright (C) 2021 Hubert Bossy

#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.

#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to:
#  The Free Software Foundation, Inc.
#  59 Temple Place - Suite 330
#  Boston, MA  02111-1307
#  USA.

#  As a special exception, if other files instantiate templates or
#  use macros or inline functions from this file, or you compile
#  this file and link it with other works to produce a work based
#  on this file, this file does not by itself cause the resulting
#  work to be covered by the GNU General Public License. However
#  the source code for this file must still be made available in
#  accordance with section (3) of the GNU General Public License.

#  This exception does not invalidate any other reasons why a work
#  based on this file might be covered by the GNU General Public
#  License.


# Parse MSTP or Bacnet over RS485 frames. Use with Async Serial
from distutils.debug import DEBUG
from tkinter import Frame
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta
DEBUG = False

MSTP_RECEIVE_STATE_IDLE = 0,
MSTP_RECEIVE_STATE_PREAMBLE = 1,
MSTP_RECEIVE_STATE_HEADER = 2,
MSTP_RECEIVE_STATE_DATA = 3,
MSTP_RECEIVE_STATE_SKIP_DATA = 4



FRAME_TYPE_TOKEN  = 0
FRAME_TYPE_POLL_FOR_MASTER  = 1
FRAME_TYPE_REPLY_TO_POLL_FOR_MASTER  = 2
FRAME_TYPE_TEST_REQUEST  = 3
FRAME_TYPE_TEST_RESPONSE  = 4
FRAME_TYPE_BACNET_DATA_EXPECTING_REPLY  = 5
FRAME_TYPE_BACNET_DATA_NOT_EXPECTING_REPLY  = 6
FRAME_TYPE_REPLY_POSTPONED  = 7

frame_types_txts = {
    FRAME_TYPE_TOKEN: 'TOKEN',
    FRAME_TYPE_POLL_FOR_MASTER: 'POLL_FOR_MASTER',
    FRAME_TYPE_REPLY_TO_POLL_FOR_MASTER: 'REPLY_TO_POLL_FOR_MASTER',
    FRAME_TYPE_TEST_REQUEST: 'TEST_REQUEST',
    FRAME_TYPE_TEST_RESPONSE: 'TEST_RESPONSE',
    FRAME_TYPE_BACNET_DATA_EXPECTING_REPLY: 'BACNET_DATA_EXPECTING_REPLY',
    FRAME_TYPE_BACNET_DATA_NOT_EXPECTING_REPLY: 'BACNET_DATA_NOT_EXPECTING_REPLY',
    FRAME_TYPE_REPLY_POSTPONED: 'REPLY_POSTPONED'
}

# crc tables taken from bacnet stack (C) Steve Karg
header_crc_table = [ 0x00, 0xfe, 0xff, 0x01, 0xfd, 0x03,
    0x02, 0xfc, 0xf9, 0x07, 0x06, 0xf8, 0x04, 0xfa, 0xfb, 0x05, 0xf1, 0x0f,
    0x0e, 0xf0, 0x0c, 0xf2, 0xf3, 0x0d, 0x08, 0xf6, 0xf7, 0x09, 0xf5, 0x0b,
    0x0a, 0xf4, 0xe1, 0x1f, 0x1e, 0xe0, 0x1c, 0xe2, 0xe3, 0x1d, 0x18, 0xe6,
    0xe7, 0x19, 0xe5, 0x1b, 0x1a, 0xe4, 0x10, 0xee, 0xef, 0x11, 0xed, 0x13,
    0x12, 0xec, 0xe9, 0x17, 0x16, 0xe8, 0x14, 0xea, 0xeb, 0x15, 0xc1, 0x3f,
    0x3e, 0xc0, 0x3c, 0xc2, 0xc3, 0x3d, 0x38, 0xc6, 0xc7, 0x39, 0xc5, 0x3b,
    0x3a, 0xc4, 0x30, 0xce, 0xcf, 0x31, 0xcd, 0x33, 0x32, 0xcc, 0xc9, 0x37,
    0x36, 0xc8, 0x34, 0xca, 0xcb, 0x35, 0x20, 0xde, 0xdf, 0x21, 0xdd, 0x23,
    0x22, 0xdc, 0xd9, 0x27, 0x26, 0xd8, 0x24, 0xda, 0xdb, 0x25, 0xd1, 0x2f,
    0x2e, 0xd0, 0x2c, 0xd2, 0xd3, 0x2d, 0x28, 0xd6, 0xd7, 0x29, 0xd5, 0x2b,
    0x2a, 0xd4, 0x81, 0x7f, 0x7e, 0x80, 0x7c, 0x82, 0x83, 0x7d, 0x78, 0x86,
    0x87, 0x79, 0x85, 0x7b, 0x7a, 0x84, 0x70, 0x8e, 0x8f, 0x71, 0x8d, 0x73,
    0x72, 0x8c, 0x89, 0x77, 0x76, 0x88, 0x74, 0x8a, 0x8b, 0x75, 0x60, 0x9e,
    0x9f, 0x61, 0x9d, 0x63, 0x62, 0x9c, 0x99, 0x67, 0x66, 0x98, 0x64, 0x9a,
    0x9b, 0x65, 0x91, 0x6f, 0x6e, 0x90, 0x6c, 0x92, 0x93, 0x6d, 0x68, 0x96,
    0x97, 0x69, 0x95, 0x6b, 0x6a, 0x94, 0x40, 0xbe, 0xbf, 0x41, 0xbd, 0x43,
    0x42, 0xbc, 0xb9, 0x47, 0x46, 0xb8, 0x44, 0xba, 0xbb, 0x45, 0xb1, 0x4f,
    0x4e, 0xb0, 0x4c, 0xb2, 0xb3, 0x4d, 0x48, 0xb6, 0xb7, 0x49, 0xb5, 0x4b,
    0x4a, 0xb4, 0xa1, 0x5f, 0x5e, 0xa0, 0x5c, 0xa2, 0xa3, 0x5d, 0x58, 0xa6,
    0xa7, 0x59, 0xa5, 0x5b, 0x5a, 0xa4, 0x50, 0xae, 0xaf, 0x51, 0xad, 0x53,
    0x52, 0xac, 0xa9, 0x57, 0x56, 0xa8, 0x54, 0xaa, 0xab, 0x55 ]

data_crc_table = [ 0x0000, 0x1189, 0x2312, 0x329b, 0x4624,
    0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5,
    0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7,
    0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a,
    0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
    0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9,
    0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f,
    0x0420, 0x15a9, 0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868,
    0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528,
    0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb,
    0xaa72, 0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387,
    0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46,
    0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a,
    0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb,
    0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad,
    0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c,
    0x7df7, 0x6c7e, 0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c,
    0xd1b5, 0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3,
    0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c, 0xc60c, 0xd785,
    0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956,
    0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416,
    0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1,
    0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
    0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70,
    0x1ff9, 0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78 ]

def crc_calc_header( data_value : int, crc_value : int):
    return header_crc_table[crc_value ^ data_value]

def crc_calc_data(data_value : int, crc_value : int):
    return ((crc_value >> 8) ^ data_crc_table[(crc_value & 0x00FF) ^ data_value])

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    timeout_setting = NumberSetting(min_value=0, max_value=100)

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'MSTPFrame': {
            'format': 'type: {{data.frame_type}}, dst: {{data.dst_addr}}, src: {{data.src_addr}}, data length: {{data.data_len}}, header crc:{{data.header_crc}}',
        },
        'MSTPFrameWithBytes': {
            'format': 'type: {{data.frame_type}}, dst: {{data.dst_addr}}, src: {{data.src_addr}}, data length: {{data.data_len}}, header crc:{{data.header_crc}}, data crc:{{data.data_crc}}, data bytes:{{data.data_bytes}}',
        },        
        'MalformedMSTPFrame': {
            'format': 'Malformed frame: error: {{data.error}}, type: {{data.frame_type}}, dst: {{data.dst_addr}}, src: {{data.src_addr}}, header crc:{{data.header_crc}}'        
        },
        
    }
    

    def receive_fsm(self, octet, timestamp):
        data_register = int.from_bytes(octet, 'big')
        # if DEBUG: print('receive_fsm data:', hex(data_register), 'timestamp', timestamp)
        if self.receive_state == MSTP_RECEIVE_STATE_IDLE:
            if DEBUG: print('MSTP_RECEIVE_STATE_IDLE')
            self.start_time = timestamp
            self.mstp_frame = {
                'data' : [],
                'src_addr' : None, 
                'dst_addr' : None,
                'frame_type' : None,
                'len' : 0,
                'actual_header_crc': None,
                'data_actual_crc_msb': None,
                'data_actual_crc_lsb': None
            }
            self.data = []

            # In the IDLE state, the node waits for the beginning of a frame.
            if data_register == 0x55:
                self.last_timestamp = timestamp
                # Preamble1
                self.receive_state = MSTP_RECEIVE_STATE_PREAMBLE
        elif self.receive_state == MSTP_RECEIVE_STATE_PREAMBLE:
            if DEBUG: print('MSTP_RECEIVE_STATE_PREAMBLE')
            # if DEBUG: print('time diff:', timestamp - self.last_timestamp)
            if timestamp - self.last_timestamp > self.timeout:
                self.mstp_frame.update({'valid' : False, 'error': 'timeout'})
                self.receive_state = MSTP_RECEIVE_STATE_IDLE
            # In the PREAMBLE state, the node waits for the
            #    second octet of the preamble.
            elif data_register == 0xFF:                
                self.last_timestamp = timestamp
                # Preamble2
                self.index = 0
                self.header_crc = 0xFF
                # receive the remainder of the frame.
                self.receive_state = MSTP_RECEIVE_STATE_HEADER
            elif data_register == 0x55:
                # ignore RepeatedPreamble1
                self.receive_state = MSTP_RECEIVE_STATE_PREAMBLE
            else:
                # not preamble
                self.receive_state = MSTP_RECEIVE_STATE_IDLE
        elif self.receive_state == MSTP_RECEIVE_STATE_HEADER:
            if DEBUG: print('MSTP_RECEIVE_STATE_HEADER')
            if timestamp - self.last_timestamp > self.timeout:
                self.receive_state = MSTP_RECEIVE_STATE_IDLE
                self.mstp_frame.update({'valid' : False, 'error': 'timeout'})
                # invalid frame
            elif self.index == 0:
                self.last_timestamp = timestamp
                self.header_crc = crc_calc_header( data_register, self.header_crc)      
                self.mstp_frame_type = data_register
                self.mstp_frame.update({'frame_type' : data_register})
                if DEBUG: print('frame_type:', data_register)
                self.index = 1
            elif self.index == 1:
                self.last_timestamp = timestamp
                self.header_crc = crc_calc_header( data_register, self.header_crc)      
                self.mstp_frame.update({'dst_addr' : data_register})
                if DEBUG: print('dst_addr:', hex(data_register))
                self.index = 2
            elif self.index == 2:
                self.last_timestamp = timestamp
                self.header_crc = crc_calc_header( data_register, self.header_crc)      
                self.mstp_frame.update({'src_addr' : data_register})
                if DEBUG: print('src_addr:', hex(data_register))
                self.index = 3
            elif self.index == 3:
                self.last_timestamp = timestamp
                self.header_crc = crc_calc_header( data_register, self.header_crc)      
                self.mstp_frame.update({'len' : data_register * 256})
                self.index = 4            
            elif self.index == 4:
                self.last_timestamp = timestamp
                self.header_crc = crc_calc_header( data_register, self.header_crc)      
                self.mstp_frame.update({'len' : self.mstp_frame['len'] + data_register})
                self.index = 5 
                if DEBUG: print('len:', self.mstp_frame['len'])
            elif self.index == 5:
                self.last_timestamp = timestamp
                # In the HEADER_CRC state, the node validates the CRC
                #    on the fixed  message header.
                self.header_crc = crc_calc_header( data_register, self.header_crc) 
                self.mstp_frame.update({'actual_header_crc': data_register})
                if DEBUG: print('header_crc:', hex(self.header_crc))     
                if self.header_crc != 0x55:
                    # BadCRC */
                    # indicate that an error has occurred during
                    # the reception of a frame                    
                    self.mstp_frame.update({'invalid_header_crc' : True})
                    self.mstp_frame.update({'valid' : False, 'error': 'bad header CRC'})
                    self.receive_state = MSTP_RECEIVE_STATE_IDLE
                    if DEBUG: print('ivalid crc header')
                    if DEBUG: print(self.mstp_frame)     
                else:
                    if DEBUG: print('header crc ok')
                    self.mstp_frame.update({'invalid_header_crc' : False})
                    if self.mstp_frame['len'] == 0:
                        if DEBUG: print('len == 0, frame valid')
                        # No data
                        self.receive_state = MSTP_RECEIVE_STATE_IDLE
                        self.mstp_frame.update({'valid' : True})
                    else:
                        # Data
                        self.receive_state = MSTP_RECEIVE_STATE_DATA
                        self.index = 0
                        self.data_crc = 0xFFFF

        elif ( self.receive_state == MSTP_RECEIVE_STATE_DATA or
            self.receive_state == MSTP_RECEIVE_STATE_DATA):
            if DEBUG: print('MSTP_RECEIVE_STATE_DATA')
            if DEBUG: print('data[{}]: 0x{:02X}, timestamp: {}'.format(self.index, data_register, timestamp) )

            if timestamp - self.last_timestamp > self.timeout:
                self.receive_state = MSTP_RECEIVE_STATE_IDLE
                # invalid frame   
                self.mstp_frame.update({'valid' : False, 'error': 'timeout'})
            elif self.index < self.mstp_frame['len']:
                self.last_timestamp = timestamp
                # data octet
                self.data_crc = crc_calc_data( data_register, self.data_crc)      
                self.data.append(data_register)
                # print(self.data)
                self.index += 1
                # SKIP_DATA or DATA - no change in state
            elif self.index == self.mstp_frame['len']:
                self.last_timestamp = timestamp
                self.mstp_frame.update({'data' : self.data})
                # CRC 1
                self.data_crc = crc_calc_data( data_register, self.data_crc)      
                self.mstp_frame.update({'data_actual_crc_msb' : data_register})
                self.index += 1
            elif self.index == self.mstp_frame['len']+1:
                self.last_timestamp = timestamp
                # CRC 2
                self.data_crc = crc_calc_data( data_register, self.data_crc)      
                self.mstp_frame.update({'data_actual_crc_lsb' : data_register})                
                # STATE DATA CRC - no need for new state
                # indicate the complete reception of a valid frame
                if self.data_crc == 0xF0B8:
                    self.mstp_frame.update({'valid' : True})
                else:
                    self.mstp_frame.update({'valid' : False, 'error': 'bad data CRC'})
                self.receive_state = MSTP_RECEIVE_STATE_IDLE
        self.mstp_frame.update({'end_time' : timestamp})  

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        if DEBUG: print("Settings:",
              self.timeout_setting)

        self.receive_state = MSTP_RECEIVE_STATE_IDLE
        self.data_crc = 0 
        self.header_crc = 0
        self.index = 0
        self.last_timestamp = 0
        self.timeout =  GraphTimeDelta(millisecond = self.timeout_setting)
        self.mstp_frame = {}
        self.data = []

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        self.receive_fsm(octet=frame.data['data'], timestamp=frame.start_time)

        if 'valid' in self.mstp_frame.keys():
            if self.mstp_frame['valid']:
                if DEBUG: print('returning valid frame')
                if self.mstp_frame['len'] > 0:
                    return AnalyzerFrame('MSTPFrameWithBytes', self.start_time, frame.end_time,
                        {'frame_type': frame_types_txts[self.mstp_frame['frame_type']],
                        'src_addr': f"0x{self.mstp_frame['src_addr']:02X}",
                        'dst_addr': f"0x{self.mstp_frame['dst_addr']:02X}",
                        'data_len': self.mstp_frame['len'],
                        'header_crc' : f"0x{self.mstp_frame['actual_header_crc']:02X}",
                        'data_crc' : f"0x{self.mstp_frame['data_actual_crc_msb']:02X}{self.mstp_frame['data_actual_crc_lsb']:02X}",
                        'data_bytes': '[{} ]'.format(' '.join( [ f'0x{v:02X}' for v in self.mstp_frame['data']]))
                        })
                else: 
                    return AnalyzerFrame('MSTPFrame', self.start_time, frame.end_time,
                        {'frame_type': frame_types_txts[self.mstp_frame['frame_type']],
                        'src_addr': f"0x{self.mstp_frame['src_addr']:02X}",
                        'dst_addr': f"0x{self.mstp_frame['dst_addr']:02X}",
                        'data_len': self.mstp_frame['len'],
                        'header_crc' : f"0x{self.mstp_frame['actual_header_crc']:02X}",
                        })
            else:
                return AnalyzerFrame('MalformedMSTPFrame', self.start_time, frame.end_time,
                    {'frame_type': frame_types_txts[self.mstp_frame['frame_type']],
                    'src_addr': f"0x{self.mstp_frame['src_addr']:02X}",
                    'dst_addr': f"0x{self.mstp_frame['dst_addr']:02X}",
                    'data_len': self.mstp_frame['len'],
                    'actual_header_crc': self.mstp_frame['actual_header_crc'],
                    'error': self.mstp_frame['error']
                    })

        return None
