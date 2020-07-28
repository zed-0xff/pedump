#!/usr/bin/env python
# based on code from http://trendystephen.blogspot.be/2008/01/rich-header.html
import sys
import struct

# I'm trying not to bury the magic number...
CHECKSUM_MASK = 0x536e6144 # DanS (actuall SnaD)
RICH_TEXT = 'Rich'
RICH_TEXT_LENGTH = len(RICH_TEXT)
PE_START = 0x3c
PE_FIELD_LENGTH = 4

# most of values up to AliasObj900 are from old MSVC leak with private PDBs; 
# rest is from guesses/observations
PRODID_MAP = {
  0: "Unknown",
  1: "Import0",
  2: "Linker510",
  3: "Cvtomf510",
  4: "Linker600",
  5: "Cvtomf600",
  6: "Cvtres500",
  7: "Utc11_Basic",
  8: "Utc11_C",
  9: "Utc12_Basic",
  10: "Utc12_C",
  11: "Utc12_CPP",
  12: "AliasObj60",
  13: "VisualBasic60",
  14: "Masm613",
  15: "Masm710",
  16: "Linker511",
  17: "Cvtomf511",
  18: "Masm614",
  19: "Linker512",
  20: "Cvtomf512",
  21: "Utc12_C_Std",
  22: "Utc12_CPP_Std",
  23: "Utc12_C_Book",
  24: "Utc12_CPP_Book",
  25: "Implib700",
  26: "Cvtomf700",
  27: "Utc13_Basic",
  28: "Utc13_C",
  29: "Utc13_CPP",
  30: "Linker610",
  31: "Cvtomf610",
  32: "Linker601",
  33: "Cvtomf601",
  34: "Utc12_1_Basic",
  35: "Utc12_1_C",
  36: "Utc12_1_CPP",
  37: "Linker620",
  38: "Cvtomf620",
  39: "AliasObj70",
  40: "Linker621",
  41: "Cvtomf621",
  42: "Masm615",
  43: "Utc13_LTCG_C",
  44: "Utc13_LTCG_CPP",
  45: "Masm620",
  46: "ILAsm100",
  47: "Utc12_2_Basic",
  48: "Utc12_2_C",
  49: "Utc12_2_CPP",
  50: "Utc12_2_C_Std",
  51: "Utc12_2_CPP_Std",
  52: "Utc12_2_C_Book",
  53: "Utc12_2_CPP_Book",
  54: "Implib622",
  55: "Cvtomf622",
  56: "Cvtres501",
  57: "Utc13_C_Std",
  58: "Utc13_CPP_Std",
  59: "Cvtpgd1300",
  60: "Linker622",
  61: "Linker700",
  62: "Export622",
  63: "Export700",
  64: "Masm700",
  65: "Utc13_POGO_I_C",
  66: "Utc13_POGO_I_CPP",
  67: "Utc13_POGO_O_C",
  68: "Utc13_POGO_O_CPP",
  69: "Cvtres700",
  70: "Cvtres710p",
  71: "Linker710p",
  72: "Cvtomf710p",
  73: "Export710p",
  74: "Implib710p",
  75: "Masm710p",
  76: "Utc1310p_C",
  77: "Utc1310p_CPP",
  78: "Utc1310p_C_Std",
  79: "Utc1310p_CPP_Std",
  80: "Utc1310p_LTCG_C",
  81: "Utc1310p_LTCG_CPP",
  82: "Utc1310p_POGO_I_C",
  83: "Utc1310p_POGO_I_CPP",
  84: "Utc1310p_POGO_O_C",
  85: "Utc1310p_POGO_O_CPP",
  86: "Linker624",
  87: "Cvtomf624",
  88: "Export624",
  89: "Implib624",
  90: "Linker710",
  91: "Cvtomf710",
  92: "Export710",
  93: "Implib710",
  94: "Cvtres710",
  95: "Utc1310_C",
  96: "Utc1310_CPP",
  97: "Utc1310_C_Std",
  98: "Utc1310_CPP_Std",
  99: "Utc1310_LTCG_C",
  100: "Utc1310_LTCG_CPP",
  101: "Utc1310_POGO_I_C",
  102: "Utc1310_POGO_I_CPP",
  103: "Utc1310_POGO_O_C",
  104: "Utc1310_POGO_O_CPP",
  105: "AliasObj710",
  106: "AliasObj710p",
  107: "Cvtpgd1310",
  108: "Cvtpgd1310p",
  109: "Utc1400_C",
  110: "Utc1400_CPP",
  111: "Utc1400_C_Std",
  112: "Utc1400_CPP_Std",
  113: "Utc1400_LTCG_C",
  114: "Utc1400_LTCG_CPP",
  115: "Utc1400_POGO_I_C",
  116: "Utc1400_POGO_I_CPP",
  117: "Utc1400_POGO_O_C",
  118: "Utc1400_POGO_O_CPP",
  119: "Cvtpgd1400",
  120: "Linker800",
  121: "Cvtomf800",
  122: "Export800",
  123: "Implib800",
  124: "Cvtres800",
  125: "Masm800",
  126: "AliasObj800",
  127: "PhoenixPrerelease",
  128: "Utc1400_CVTCIL_C",
  129: "Utc1400_CVTCIL_CPP",
  130: "Utc1400_LTCG_MSIL",
  131: "Utc1500_C",
  132: "Utc1500_CPP",
  133: "Utc1500_C_Std",
  134: "Utc1500_CPP_Std",
  135: "Utc1500_CVTCIL_C",
  136: "Utc1500_CVTCIL_CPP",
  137: "Utc1500_LTCG_C",
  138: "Utc1500_LTCG_CPP",
  139: "Utc1500_LTCG_MSIL",
  140: "Utc1500_POGO_I_C",
  141: "Utc1500_POGO_I_CPP",
  142: "Utc1500_POGO_O_C",
  143: "Utc1500_POGO_O_CPP",

  144: "Cvtpgd1500",
  145: "Linker900",
  146: "Export900",
  147: "Implib900",
  148: "Cvtres900",
  149: "Masm900",
  150: "AliasObj900",
  151: "Resource900",

  152: "AliasObj1000",
  154: "Cvtres1000",
  155: "Export1000",
  156: "Implib1000",
  157: "Linker1000",
  158: "Masm1000",

  170: "Utc1600_C",
  171: "Utc1600_CPP",
  172: "Utc1600_CVTCIL_C",
  173: "Utc1600_CVTCIL_CPP",
  174: "Utc1600_LTCG_C ",
  175: "Utc1600_LTCG_CPP",
  176: "Utc1600_LTCG_MSIL",
  177: "Utc1600_POGO_I_C",
  178: "Utc1600_POGO_I_CPP",
  179: "Utc1600_POGO_O_C",
  180: "Utc1600_POGO_O_CPP",
  
  # vvv
  183: "Linker1010",
  184: "Export1010",
  185: "Implib1010",
  186: "Cvtres1010",
  187: "Masm1010",
  188: "AliasObj1010",
  # ^^^

  199: "AliasObj1100",
  201: "Cvtres1100",
  202: "Export1100",
  203: "Implib1100",
  204: "Linker1100",
  205: "Masm1100",

  206: "Utc1700_C",
  207: "Utc1700_CPP",
  208: "Utc1700_CVTCIL_C",
  209: "Utc1700_CVTCIL_CPP",
  210: "Utc1700_LTCG_C ",
  211: "Utc1700_LTCG_CPP",
  212: "Utc1700_LTCG_MSIL",
  213: "Utc1700_POGO_I_C",
  214: "Utc1700_POGO_I_CPP",
  215: "Utc1700_POGO_O_C",
  216: "Utc1700_POGO_O_CPP",
}

##
# A convenient exception to raise if the Rich Header doesn't exist.
class RichHeaderNotFoundException(Exception):
    def __init__(self):
        Exception.__init__(self, "Rich footer does not appear to exist")

##
# Locate the body of the data that contains the rich header This will be
# (roughly) between 0x3c and the beginning of the PE header, but the entire
# thing up to the last checksum will be needed in order to verify the header.
def get_file_header(file_name):
    f = open(file_name,'rb')

    #start with 0x3c
    f.seek(PE_START)
    data = f.read(PE_FIELD_LENGTH)

    if data == '': #File is empty, bail
        raise RichHeaderNotFoundException()
    end = struct.unpack('<L',data)[0] # get the value at 0x3c

    f.seek(0)
    data = f.read( end ) # read until that value is reached
    f.close()

    return data

##
# This class assists in parsing the Rich Header from PE Files.
# The Rich Header is the section in the PE file following the dos stub but
# preceding the lfa_new header which is inserted by link.exe when building with
# the Microsoft Compilers.  The Rich Heder contains the following:
# <pre>
# marker, checksum, checksum, checksum, 
# R_compid_i, R_occurrence_i, 
# R_compid_i+1, R_occurrence_i+1, ...  
# R_compid_N-1, R_occurrence_N-1, Rich, marker
#
# marker = checksum XOR 0x536e6144
# R_compid_i is the ith compid XORed with the checksum
# R_occurrence_i is the ith occurrence  XORed with the checksum
# Rich = the text string 'Rich'
# The checksum is the sum of all the PE Header values rotated by their
# offset and the sum of all compids rotated by their occurrence counts.  
# </pre>
# @see _validate_checksum code for checksum calculation
class ParsedRichHeader:
    ##
    # Creates a ParsedRichHeader from the specified PE File.
    # @throws RichHeaderNotFoundException if the file does not contain a rich header
    # @param file_name The PE File to be parsed
    def __init__(self, file_name):
        ## The file that was parsed
        self.file_name = file_name
        self._parse( file_name )

    ##
    # Used internally to parse the PE File and extract Rich Header data.
    # Initializes self.compids and self.valid_checksum. 
    # @param file_name The PE File to be parsed
    # @throws RichHeaderNotFoundException if the file does not contain a rich header
    def _parse(self,file_name):
        #make sure there is a header:
        data = get_file_header( file_name )

        compid_end_index = data.find(RICH_TEXT) 
        if compid_end_index == -1:
            raise RichHeaderNotFoundException()

        rich_offset = compid_end_index + RICH_TEXT_LENGTH

        checksum_text = data[rich_offset:rich_offset+4] 
        checksum_value = struct.unpack('<L', checksum_text)[0]
        #start marker denotes the beginning of the rich header
        start_marker = struct.pack('<LLLL',checksum_value ^ CHECKSUM_MASK, checksum_value, checksum_value, checksum_value )[0] 

        rich_header_start = data.find(start_marker)
        if rich_header_start == -1:
            raise RichHeaderNotFoundException()

        compid_start_index = rich_header_start + 16 # move past the marker and 3 checksums

        compids = dict()
        for i in range(compid_start_index, compid_end_index, 8):
            compid = struct.unpack('<L',data[i:i+4])[0] ^ checksum_value
            count = struct.unpack('<L',data[i+4:i+8])[0] ^ checksum_value
            compids[compid]=count
        
        ## A dictionary of compids and their occurrence counts
        self.compids = compids
        ## A value for later reference to see if the checksum was valid
        self.valid_checksum = self._validate_checksum( data, rich_header_start, checksum_value )

    ##
    # Compute the checksum value and see if it matches the checksum stored in
    # the Rich Header.
    # The checksum is the sum of all the PE Header values rotated by their
    # offset and the sum of all compids rotated by their occurrence counts
    # @param data A blob of binary data that corresponds to the PE Header data
    # @param rich_header_start The offset to marker, checksum, checksum, checksum
    # @returns True if the checksum is valid, false otherwise
    def _validate_checksum(self, data, rich_header_start, checksum):

        #initialize the checksum offset at which the rich header is located
        cksum = rich_header_start

        #add the value from the pe header after rotating the value by its offset in the pe header
        for i in range(0,rich_header_start):
            if PE_START <= i <= PE_START+PE_FIELD_LENGTH-1:
                continue
            temp = ord(data[i])
            cksum+= ((temp << (i%32)) | (temp >> (32-(i%32))) & 0xff)
            cksum &=0xffffffff

        #add each compid to the checksum after rotating it by its occurrence count
        for k in self.compids.keys():
            cksum += (k << self.compids[k]%32 | k >> ( 32 - (self.compids[k]%32)))
            cksum &=0xffffffff

        ## A convenient place for storing the checksum that was computing during checksum validation
        self.checksum = cksum

        return cksum == checksum

if __name__ == "__main__":
    ph = ParsedRichHeader(sys.argv[1])
    print ("PRODID   name            build count")
    for key in ph.compids.keys():
        count = ph.compids[key]
        prodid, build = (key>>16), key&0xFFFF
        prodid_name = PRODID_MAP[prodid] if prodid in PRODID_MAP else "<unknown>"
        print ('%6d   %-15s %5d %5d' % (prodid, prodid_name, build, count))
    if ph.valid_checksum:
        print ("Checksum valid")
    else:
        print("Checksum not valid!")
