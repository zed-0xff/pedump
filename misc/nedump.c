/* Windows/DOS NE (New Executable) dumper
 *
 * Copyright (C) 2012 Daniel Collins <solemnwarning@solemnwarning.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 *	* Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 *	* Neither the name of the developer nor the names of its contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEVELOPER BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Version history:
 *
 * 2012-01-12:
 *	Initial release
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define FLAG_CAT(dest, src, cond) \
	if(cond) { \
		strcat(dest, dest[0] ? (" | " src) : src); \
	}

#define MZ_MAGIC 0x5A4D

struct mz_header {
	unsigned short magic;
	unsigned short bytes_in_last_block;
	unsigned short blocks_in_file;
	unsigned short num_relocs;
	unsigned short header_paragraphs;
	unsigned short min_extra_paragraphs;
	unsigned short max_extra_paragraphs;
	unsigned short ss;
	unsigned short sp;
	unsigned short checksum;
	unsigned short ip;
	unsigned short cs;
	unsigned short reloc_table_offset;
	unsigned short overlay_number;
};

#define NE_MAGIC 0x454E

#define NE_FLAG_SINGLEDATA 0x0001
#define NE_FLAG_MULTIPLEDATA 0x0002
#define NE_FLAG_LIBRARY 0x8000

#define NE_EXE_WINDOWS 0x02

struct ne_header {
	/* Offsets relative to beginning of NE header */
	
	unsigned short magic;
	unsigned char linker_ver;
	unsigned char linker_rev;
	unsigned short entry_table_offset;
	unsigned short entry_table_size;
	unsigned int whole_file_crc;
	unsigned short flags;
	unsigned short auto_data_segment;
	unsigned short init_heap_size;
	unsigned short init_stack_size;
	unsigned short ip;
	unsigned short cs;
	unsigned short ss;
	unsigned short sp;
	unsigned short seg_table_entries;
	unsigned short mod_ref_table_entries;
	unsigned short non_res_name_table_entries;
	unsigned short seg_table_offset;
	unsigned short res_table_offset;
	unsigned short res_name_table_offset;
	unsigned short mod_ref_table_offset;
	unsigned short import_table_offset;
	unsigned int non_res_name_table_offset;	/* Relative to start of file */
	unsigned short entry_table_movable_entries;
	unsigned short seg_sector_size_shift;
	unsigned short res_table_entries;
	unsigned char exe_type;
};

struct import_table {
	unsigned char name_len;
	char name[256];
};

struct export_table {
	unsigned char name_len;
	char name[256];
	
	unsigned short ordinal;
}  __attribute__((__packed__));

struct entry_bundle {
	unsigned char bundle_entries;
	unsigned char segment_indicator;
};

struct fixed_entry {
	unsigned char flags;
	unsigned short seg_offset;
} __attribute__((__packed__));

struct moveable_entry {
	unsigned char flags;
	unsigned short padding;
	unsigned char seg_num;
	unsigned short seg_offset;
} __attribute__((__packed__));

#define SEG_TYPE_MASK	0x0007
#define SEG_CODE	0x0000
#define SEG_DATA	0x0001
#define SEG_MOVEABLE	0x0010
#define SEG_PRELOAD	0x0040
#define SEG_RELOCINFO	0x0100
#define SEG_DISCARD	0xF000

struct segment_table {
	unsigned short offset;	/* Measured in sectors, zero means no data */
	unsigned short size;	/* Measured in bytes, zero means 64KiB */
	unsigned short flags;
	unsigned short alloc;	/* Minimum allocation size, zero means 64KiB */
};

#define RELOC_LOBYTE 0x00
#define RELOC_SEGMENT 0x02
#define RELOC_FAR_ADDR 0x03
#define RELOC_OFFSET 0x05

#define RELOC_TARGET_MASK 0x03
#define RELOC_INTERNALREF 0x00
#define RELOC_IMPORTORDINAL 0x01
#define RELOC_IMPORTNAME 0x02
#define RELOC_OSFIXUP 0x03
#define RELOC_ADDITIVE 0x04

struct segment_reloc {
	unsigned char src_type;
	unsigned char flags;
	unsigned short offset;
	
	union {
		struct {
			unsigned char seg_num;
			unsigned char zero;
			unsigned short offset;
		} internalref;
		
		struct {
			unsigned short mod_index;
			unsigned short name_offset;
		} importname;
		
		struct {
			unsigned short mod_index;
			unsigned short ordinal;
		} importordinal;
		
		struct {
			unsigned short fixup_type;
			unsigned short zero;
		} osfixup;
		
		unsigned char target_b[4];
		unsigned short target_w[2];
	};
};

#define RESOURCE_HO 0x8000

struct resource_table_type {
	unsigned short type_id;
	unsigned short res_count;
	unsigned int padding;
};

#define RESOURCE_MOVEABLE	0x0010
#define RESOURCE_PURE		0x0020
#define RESOURCE_PRELOAD	0x0040

struct resource_table_entry {
	unsigned short offset;
	unsigned short length;
	
	unsigned short flags;
	unsigned short res_id;
	
	unsigned int padding;
};

struct import_entry {
	char module[256];
	
	char name[256];
	int ordinal;
	
	struct import_entry *next;
};

FILE *fh;

size_t read_data(char *buf, size_t offset, size_t size) {
	if(fseek(fh, offset, SEEK_SET) == -1) {
		return 0;
	}
	
	size_t s = 0, r;
	
	while(s < size) {
		if((r = fread(buf + s, 1, size - s, fh)) == 0) {
			break;
		}
		
		s += r;
	}
	
	if(ferror(fh)) {
		fprintf(stderr, "Read error\n");
		exit(1);
	}
	
	return s;
}

void add_import(struct import_entry **list, const char *module, const char *name, int ordinal) {
	while(*list && strcasecmp((*list)->module, module) < 0) {
		list = &((*list)->next);
	}
	
	if(name) {
		while(*list && strcasecmp((*list)->module, module) == 0 && strcasecmp((*list)->name, name) < 0) {
			list = &((*list)->next);
		}
		
		if(*list && strcasecmp((*list)->name, name) == 0) {
			return;
		}
	}else{
		while(*list && strcasecmp((*list)->module, module) == 0 && (*list)->ordinal < ordinal) {
			list = &((*list)->next);
		}
		
		if(*list && (*list)->ordinal == ordinal) {
			return;
		}
	}
	
	struct import_entry *import = malloc(sizeof(struct import_entry));
	if(!import) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(1);
	}
	
	strcpy(import->module, module);
	strcpy(import->name, name ? name : "");
	import->ordinal = ordinal;
	
	import->next = *list;
	*list = import;
}

void dump_imports(struct import_entry *imports) {
	printf("Imported names:\n");
	
	while(imports) {
		if(imports->name[0]) {
			printf("\t%s\t%s\n", imports->module, imports->name);
		}else{
			printf("\t%s\t@%d\n", imports->module, imports->ordinal);
		}
		
		imports = imports->next;
	}
}

void free_imports(struct import_entry *imports) {
	while(imports) {
		struct import_entry *d = imports;
		imports = imports->next;
		
		free(d);
	}
}

void dump_names(unsigned int res_off, unsigned int table_entries, unsigned int entry_table_off) {
	unsigned int res_num = 0;
	struct export_table exp;
	
	while(res_num < table_entries && read_data((char*)&exp, res_off, sizeof(exp)) >= 2) {
		if(exp.name_len == 0) {
			break;
		}
		
		res_off += exp.name_len + 1;
		read_data((char*)&(exp.ordinal), res_off, 2);
		res_off += 2;
		
		exp.name[exp.name_len] = '\0';
		
		if(res_num++ == 0) {
			continue;
		}
		
		/* Step through entry point table to get address */
		
		char entry_txt[64] = "WARNING: Entry point not found";
		
		unsigned int entry_off = entry_table_off, ordinal = 1, i;
		struct entry_bundle bundle;
		
		while(read_data((char*)&bundle, entry_off, sizeof(bundle)) >= 1 && bundle.bundle_entries && ordinal <= exp.ordinal) {
			entry_off += sizeof(bundle);
			
			if(bundle.segment_indicator == 0) {
				ordinal += bundle.bundle_entries;
				continue;
			}
			
			for(i = 0; i < bundle.bundle_entries; i++) {
				unsigned short seg = 0, off;
				
				if(bundle.segment_indicator == 0xFF) {
					struct moveable_entry entry;
					entry_off += read_data((char*)&entry, entry_off, sizeof(entry));
					
					seg = entry.seg_num;
					off = entry.seg_offset;
				}else{
					struct fixed_entry entry;
					entry_off += read_data((char*)&entry, entry_off, sizeof(entry));
					
					seg = bundle.segment_indicator;
					off = entry.seg_offset;
				}
				
				if(ordinal++ == exp.ordinal && seg) {
					sprintf(entry_txt, "Entry point segment: %hu, offset: 0x%04hX", seg, off);
					break;
				}
			}
		}
		
		printf("\t%s\t@%hu\t; %s\n", exp.name, exp.ordinal, entry_txt);
	}
}

void dump_ep_table(unsigned int entry_off) {
	printf("Entry point table:\n");
	
	unsigned int ordinal = 1, i;
	struct entry_bundle bundle;
	
	while(read_data((char*)&bundle, entry_off, sizeof(bundle)) >= 1 && bundle.bundle_entries) {
		entry_off += sizeof(bundle);
		
		if(bundle.segment_indicator == 0) {
			ordinal += bundle.bundle_entries;
			continue;
		}
		
		for(i = 0; i < bundle.bundle_entries; i++) {
			if(bundle.segment_indicator == 0xFF) {
				struct moveable_entry entry;
				entry_off += read_data((char*)&entry, entry_off, sizeof(entry));
				
				printf("\tOrdinal:\t%u\n", ordinal);
				printf("\tType:\t\tMoveable\n");
				printf("\tSegment number:\t%u\n", (unsigned int)entry.seg_num);
				printf("\tOffset:\t\t0x%04hX\n", entry.seg_offset);
				printf("\tFlags:\t\t0x%02X\n\n", (unsigned int)entry.flags);
			}else{
				struct fixed_entry entry;
				entry_off += read_data((char*)&entry, entry_off, sizeof(entry));
				
				printf("\tOrdinal:\t%u\n", ordinal);
				printf("\tType:\t\tFixed\n");
				printf("\tSegment number:\t%u\n", (unsigned int)bundle.segment_indicator);
				printf("\tOffset:\t\t0x%04hX\n", entry.seg_offset);
				printf("\tFlags:\t\t0x%02X\n\n", (unsigned int)entry.flags);
			}
			
			ordinal++;
		}
	}
}

void get_resource_id(char *buf, unsigned int res_table_off, unsigned short id) {
	if(id & RESOURCE_HO) {
		sprintf(buf, "%hu", id & ~RESOURCE_HO);
	}else{
		struct import_table name;
		
		read_data((char*)&name, res_table_off + id, sizeof(name));
		name.name[name.name_len] = '\0';
		
		sprintf(buf, "\"%s\"", name.name);
	}
}

void dump_resources(unsigned int res_table_off) {
	unsigned int res_off = res_table_off;
	
	unsigned short shift_count;
	res_off += read_data((char*)&shift_count, res_off, sizeof(shift_count));
	
	struct resource_table_type rt;
	
	while(read_data((char*)&rt, res_off, sizeof(rt)) >= 2 && rt.type_id) {
		res_off += sizeof(rt);
		
		char type_id[260];
		get_resource_id(type_id, res_table_off, rt.type_id);
		
		unsigned int i;
		struct resource_table_entry re;
		
		for(i = 0; i < rt.res_count; i++) {
			read_data((char*)&re, res_off, sizeof(re));
			
			char res_id[260];
			get_resource_id(res_id, res_table_off, re.res_id);
			
			unsigned int off = (unsigned int)(1 << shift_count) * re.offset;
			
			char flags[64] = "";
			
			FLAG_CAT(flags, "MOVEABLE", re.flags & RESOURCE_MOVEABLE);
			FLAG_CAT(flags, "PURE", re.flags & RESOURCE_PURE);
			FLAG_CAT(flags, "PRELOAD", re.flags & RESOURCE_PRELOAD);
			
			printf("Resource table entry at 0x%04X:\n", res_off);
			printf("\tType ID:\t%s\n", type_id);
			printf("\tResource ID:\t%s\n", res_id);
			printf("\tData offset:\t0x%04X\n", off);
			printf("\tData length:\t0x%04hX\n", re.length);
			printf("\tFlags:\t\t0x%04hX (%s)\n\n", re.flags, flags);
			
			res_off += sizeof(re);
		}
	}
}

#define DUMP_IMPORTS (int)(1<<0)
#define DUMP_SEGMENTS (int)(1<<1)
#define DUMP_RELOCATION (int)(1<<2)
#define DUMP_NONRES (int)(1<<3)
#define DUMP_RESIDENT (int)(1<<4)
#define DUMP_ENTRY (int)(1<<5)
#define DUMP_NE (int)(1<<6)
#define DUMP_MZ (int)(1<<7)
#define DUMP_RESOURCE (int)(1<<8)

int main(int argc, char **argv) {
	int opt;
	
	int to_dump = 0;
	
	while((opt = getopt(argc, argv, "isrnNehmR")) != -1) {
		switch(opt) {
			case '?':
				goto USAGE;
				
			case 'i':
				to_dump |= DUMP_IMPORTS;
				break;
			
			case 's':
				to_dump |= DUMP_SEGMENTS;
				break;
				
			case 'r':
				to_dump |= DUMP_RELOCATION;
				break;
				
			case 'n':
				to_dump |= DUMP_NONRES;
				break;
				
			case 'N':
				to_dump |= DUMP_RESIDENT;
				break;
				
			case 'e':
				to_dump |= DUMP_ENTRY;
				break;
				
			case 'h':
				to_dump |= DUMP_NE;
				break;
				
			case 'm':
				to_dump |= DUMP_MZ;
				break;
				
			case 'R':
				to_dump |= DUMP_RESOURCE;
				break;
		};
	}
	
	if(optind + 1 != argc || !to_dump) {
		USAGE:
		
		fprintf(stderr, "Usage: %s -hisrnNemR <file>\n", argv[0]);
		
		fprintf(stderr, "\t-h\tDump NE EXE header\n");
		fprintf(stderr, "\t-i\tDump detected imports\n");
		fprintf(stderr, "\t-s\tDump segment table\n");
		fprintf(stderr, "\t-r\tDump relocation information\n");
		fprintf(stderr, "\t-n\tDump exported non-resident names\n");
		fprintf(stderr, "\t-N\tDump exported resident names\n");
		fprintf(stderr, "\t-e\tDump entry points\n");
		fprintf(stderr, "\t-m\tDump MZ (DOS EXE) header\n");
		fprintf(stderr, "\t-R\tDump resource table\n");
		
		return 1;
	}
	
	if(!(fh = fopen(argv[optind], "rb"))) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}
	
	struct mz_header mz;
	
	if(read_data((char*)&mz, 0, sizeof(mz)) != sizeof(mz) || mz.magic != MZ_MAGIC) {
		fprintf(stderr, "EXE (MZ) header missing or incomplete\n");
		return 1;
	}
	
	if(to_dump & DUMP_MZ) {
		printf("MZ header information:\n");
		printf("\tNumber of pages:\t%hu\n", mz.blocks_in_file);
		printf("\tBytes in last page:\t%hu\n", mz.bytes_in_last_block);
		printf("\tRelocation table off.:\t0x%04hX\n", mz.reloc_table_offset);
		printf("\tNumber of relocations:\t%hu\n", mz.num_relocs);
		printf("\tHeader size:\t\t0x%04X\n", (unsigned int)mz.header_paragraphs * 16);
		printf("\tMinimum extra memory:\t0x%04X\n", (unsigned int)mz.min_extra_paragraphs * 16);
		printf("\tMaximum extra memory:\t0x%04X\n", (unsigned int)mz.max_extra_paragraphs * 16);
		printf("\tInitial CS:IP:\t\t0x%04hX:%04hX\n", mz.cs, mz.ip);
		printf("\tInitial SS:SP:\t\t0x%04hX:%04hX\n", mz.ss, mz.sp);
		printf("\tWhole file checksum:\t0x%04hX\n", mz.checksum);
		printf("\tOverlay number:\t\t%hu\n\n", mz.overlay_number);
	}
	
	if(mz.reloc_table_offset == 0x40) {
		unsigned int ne_offset;
		struct ne_header ne;
		
		if(read_data((char*)&ne_offset, 0x3C, 4) != 4 || read_data((char*)&ne, ne_offset, sizeof(ne)) != sizeof(ne) || ne.magic != NE_MAGIC) {
			goto NOT_NE;
		}
		
		if(to_dump & DUMP_NE) {
			printf("NE header information:\n");
			
			printf("\tHeader offset:\t\t0x%04X\n", ne_offset);
			printf("\tLinker version:\t\t%u.%u\n", (unsigned int)ne.linker_ver, (unsigned int)ne.linker_rev);
			printf("\tEntry point table:\t0x%04X\n", ne_offset + ne.entry_table_offset);
			printf("\tWhole file CRC-32:\t0x%08X\n", ne.whole_file_crc);
			
			char flags[64] = "";
			
			FLAG_CAT(flags, "NOAUTODATA", (ne.flags & 0x0003) == 0);
			FLAG_CAT(flags, "SINGLEDATA", ne.flags & 0x0001);
			FLAG_CAT(flags, "MULTIPLEDATA", ne.flags & 0x0002);
			FLAG_CAT(flags, "LIBRARY", ne.flags & 0x8000);
			
			printf("\tFlags\t\t\t0x%04X (%s)\n", (unsigned int)ne.flags, flags);
			
			printf("\tAutomatic data segment:\t%hu\n", ne.auto_data_segment);
			
			printf("\tDynamic heap size:\t0x%04hX\n", ne.init_heap_size);
			printf("\tDynamic stack size:\t0x%04hX\n", ne.init_stack_size);
			
			printf("\tInitial CS:IP:\t\t0x%04hX:%04hX\n", ne.cs, ne.ip);
			printf("\tInitial SS:SP:\t\t0x%04hX:%04hX\n", ne.ss, ne.sp);
			
			printf("\tNumber of segments:\t%hu\n", ne.seg_table_entries);
			
			printf("\tSegment table offset:\t0x%04X\n", ne_offset + ne.seg_table_offset);
			printf("\tResource table offset:\t0x%04X\n", ne_offset + ne.res_table_offset);
			printf("\tResident name table:\t0x%04X\n", ne_offset + ne.res_name_table_offset);
			printf("\tModule reference table:\t0x%04X\n", ne_offset + ne.mod_ref_table_offset);
			printf("\tImported name table:\t0x%04X\n", ne_offset + ne.import_table_offset);
			printf("\tNonResident name table:\t0x%04X\n", ne.non_res_name_table_offset);
			
			printf(
				"\tExecutable type:\t0x%02X (%s)\n\n",
				(unsigned int)ne.exe_type,
				(ne.exe_type == 0x02 ? "WINDOWS" : "UNKNOWN")
			);
		}
		
		unsigned int segments_offset = ne_offset + ne.seg_table_offset, seg_num = 0;
		struct segment_table seg;
		
		struct import_entry *imports = NULL;
		
		while(seg_num++ < ne.seg_table_entries && read_data((char*)&seg, segments_offset, sizeof(seg)) == sizeof(seg)) {
			unsigned int seg_offset = seg.offset * (1 << ne.seg_sector_size_shift);
			
			if(to_dump & DUMP_SEGMENTS) {
				char flags[64] = "";
				
				FLAG_CAT(flags, "CODE", (seg.flags & SEG_TYPE_MASK) == SEG_CODE);
				FLAG_CAT(flags, "DATA", (seg.flags & SEG_TYPE_MASK) == SEG_DATA);
				FLAG_CAT(flags, "MOVEABLE", seg.flags & SEG_MOVEABLE);
				FLAG_CAT(flags, "PRELOAD", seg.flags & SEG_PRELOAD);
				FLAG_CAT(flags, "RELOCINFO", seg.flags & SEG_RELOCINFO);
				FLAG_CAT(flags, "DISCARD", seg.flags & SEG_DISCARD);
				
				printf("Segment #%u:\n", seg_num);
				printf("\tData offset:\t\t\t0x%04X\n", seg_offset);
				printf("\tData length:\t\t\t0x%04X\n", (unsigned int)(seg.size ? seg.size : 65536));
				printf("\tMinimum allocation size:\t0x%04X\n", (unsigned int)(seg.size ? seg.size : 65536));
				printf("\tFlags:\t\t\t\t0x%04hX (%s)\n\n", seg.flags, flags);
			}
			
			segments_offset += sizeof(seg);
			
			if(seg.flags & SEG_RELOCINFO) {
				unsigned int reloc_offset = seg_offset + seg.size;
				unsigned short num_records, i;
				
				read_data((char*)&num_records, reloc_offset, 2);
				reloc_offset += 2;
				
				for(i = 0; i < num_records; i++) {
					struct segment_reloc reloc;
					
					read_data((char*)&reloc, reloc_offset, sizeof(reloc));
					
					if(to_dump & DUMP_RELOCATION) {
						unsigned short offset = reloc.offset;
						
						char src_type[64] = "", flags[64] = "";
						
						FLAG_CAT(src_type, "LOBYTE", reloc.src_type == RELOC_LOBYTE);
						FLAG_CAT(src_type, "SEGMENT", reloc.src_type == RELOC_SEGMENT);
						FLAG_CAT(src_type, "FAR_ADDR", reloc.src_type == RELOC_FAR_ADDR);
						FLAG_CAT(src_type, "OFFSET", reloc.src_type == RELOC_OFFSET);
						
						FLAG_CAT(flags, "INTERNALREF", reloc.flags & RELOC_INTERNALREF);
						FLAG_CAT(flags, "IMPORTORDINAL", reloc.flags & RELOC_IMPORTORDINAL);
						FLAG_CAT(flags, "IMPORTNAME", reloc.flags & RELOC_IMPORTNAME);
						FLAG_CAT(flags, "OSFIXUP", reloc.flags & RELOC_OSFIXUP);
						
						FLAG_CAT(flags, "ADDITIVE", reloc.flags & RELOC_ADDITIVE);
						
						printf("Relocation entry for segment #%u at 0x%04hX:\n", seg_num, reloc_offset);
						printf("\tSource type:\t\t0x%02X (%s)\n", (unsigned int)reloc.src_type, src_type);
						printf("\tFlags:\t\t\t0x%02X (%s)\n", (unsigned int)reloc.flags, flags);
						
						do {
							printf("\tOffset within segment:\t0x%04hX\n", offset);
							read_data((char*)&offset, seg_offset + offset, 2);
						} while(!(reloc.flags & RELOC_ADDITIVE) && offset != 0xFFFF);
						
						printf("\tTarget bytes:\t\t%02X %02X %02X %02X\n", (unsigned int)reloc.target_b[0], (unsigned int)reloc.target_b[1], (unsigned int)reloc.target_b[2], (unsigned int)reloc.target_b[3]);
						printf("\tTarget words:\t\t%04hX %04hX\n", reloc.target_w[0], reloc.target_w[1]);
						
						putchar('\n');
					}
					
					reloc_offset += sizeof(reloc);
					
					struct import_table mod_name, import;
					
					if(reloc.flags & (RELOC_IMPORTNAME | RELOC_IMPORTORDINAL)) {
						unsigned short mod_offset;
						read_data((char*)&mod_offset, ne_offset + ne.mod_ref_table_offset + (2 * (reloc.importordinal.mod_index - 1)), 2);
						
						read_data((char*)&mod_name, ne_offset + ne.import_table_offset + mod_offset, sizeof(mod_name));
						mod_name.name[mod_name.name_len] = '\0';
					}
					
					if(reloc.flags == RELOC_IMPORTNAME) {
						read_data((char*)&import, ne_offset + ne.import_table_offset + reloc.importname.name_offset, sizeof(import));
						import.name[import.name_len] = '\0';
						
						add_import(&imports, mod_name.name, import.name, -1);
					}
					
					if(reloc.flags == RELOC_IMPORTORDINAL) {
						add_import(&imports, mod_name.name, NULL, reloc.importordinal.ordinal);
					}
				}
			}
		}
		
		if(to_dump & DUMP_RESIDENT) {
			printf("Resident names table:\n");
			dump_names(ne_offset + ne.res_name_table_offset, 0xFFFFFFFF, ne_offset + ne.entry_table_offset);
			putchar('\n');
		}
		
		if(to_dump & DUMP_NONRES) {
			printf("Non-Resident names table:\n");
			dump_names(ne.non_res_name_table_offset, ne.non_res_name_table_entries, ne_offset + ne.entry_table_offset);
			putchar('\n');
		}
		
		if(to_dump & DUMP_ENTRY) {
			dump_ep_table(ne_offset + ne.entry_table_offset);
		}
		
		if(to_dump & DUMP_RESOURCE) {
			dump_resources(ne_offset + ne.res_table_offset);
		}
		
		if(to_dump & DUMP_IMPORTS) {
			dump_imports(imports);
		}
		
		free_imports(imports);
	}else{
		NOT_NE:
		printf("Supplied file does not appear to be in NE format\n");
	}
	
	fclose(fh);
	
	return 0;
}
