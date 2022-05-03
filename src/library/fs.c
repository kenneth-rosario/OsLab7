// fs.cpp: File System

#include "sfs/fs.h"

// #include <algorithm>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

typedef struct Bitmap {
    bool* bits; // Should be as big as the number of blocks in the disk
} Bitmap;

typedef struct InodeTableEntry {
    bool available;
} InodeTableEntry;

typedef struct InodeTable {
    InodeTableEntry* entries;
    int size;
} InodeTable;

typedef struct InodeData {
    Inode* inode;
    u_int32_t block;
    u_int32_t offset;
} InodeData;

// Init functions
void init_bitmap(Bitmap* bitmap, u_int32_t size) {
    bitmap->bits = (bool *) calloc(size, sizeof(bool));
    bitmap->bits[0] = false; // Super block is taken
    for (int i = 1; i < size; i++) bitmap->bits[i] = true; // Everything else marked as free
}

void init_inode_table(InodeTable* table, u_int32_t num_of_entries) {
    table->entries = (InodeTableEntry *) calloc(num_of_entries, sizeof(InodeTableEntry));
    for (int i = 0; i < num_of_entries; i++) {
        table->entries[i].available = true; // All Inodes are mark as available at first
    }
    table->size=num_of_entries;
}

// Book Keeping
Disk* mounted_disk; // current mounted disk
SuperBlock disk_metadata; // metadata about the disk
bool disk_registered = false; // whether a disk has been mounted to fs
Bitmap free_blocks; // free blocks bitmap
InodeTable inode_table; // stores available INodes    

// Helper functions ----------------------
u_int32_t get_inode_number_given_block_number_and_offset(u_int32_t block_number, u_int32_t inode_index_in_block) {
    return (block_number-1)*INODES_PER_BLOCK + inode_index_in_block;
}

bool get_free_inode_number(InodeTable* table, int* to_store) {
    int free_inode = -1;
    for (int i = 0; i < table->size; i++) {
        if(table->entries[i].available) {
            free_inode = i;
            break;
        }
    }
    *to_store = free_inode;
    if (free_inode >= 0) return true;
    else return false;
} 

bool load_inode(u_int32_t inode_number, Block* toStoreBlock, InodeData* toStoreIndex) {
    if (
        inode_number >= disk_metadata.Inodes || 
        inode_number < 0 ||
        !mounted_disk
    ) return false;

    u_int32_t inode_block_number=inode_number/INODES_PER_BLOCK + 1;
    u_int32_t inode_block_offset=inode_number%INODES_PER_BLOCK;

    mounted_disk->readDisk(mounted_disk, inode_block_number, toStoreBlock->Data);
    *toStoreIndex = (InodeData) {
        .block = inode_block_number,
        .offset = inode_block_offset,
        .inode = toStoreBlock->Inodes + inode_block_offset
    };
    return true;
}

// Debug file system -----------------------------------------------------------
void debug(Disk *disk) {
    Block super_block;

    // Read Superblock
    disk->readDisk(disk, 0, super_block.Data);
    
    printf("SuperBlock:\n");
    printf("    magic number is %s\n", (super_block.Super.MagicNumber == MAGIC_NUMBER ? "valid" : "invalid"));
    printf("    %u blocks\n", super_block.Super.Blocks);
    printf("    %u inode blocks\n", super_block.Super.InodeBlocks);
    printf("    %u inodes\n", super_block.Super.Inodes);

    // Read Inode blocks
    int num_of_inode_blocks = super_block.Super.InodeBlocks;

    if (num_of_inode_blocks == 0)
        return;

    Block InodeBlock;
    for (int i = 1; i <= num_of_inode_blocks; i++) {
        disk->readDisk(disk, i, InodeBlock.Data);
        // iterate over inodes
        for (u_int32_t j = 0; j < INODES_PER_BLOCK; j++) {
            Inode current_inode = InodeBlock.Inodes[j];
            if (current_inode.Valid == 0) {
                continue;
            }
            printf("Inode %d:\n", j);
            printf("    size: %u bytes\n", current_inode.Size);
            printf("    direct blocks:");
            for (u_int32_t k = 0; k < POINTERS_PER_INODE; k++) {
                if (current_inode.Direct[k]) {
                    printf(" %u", current_inode.Direct[k]);
                }
            }
            printf("\n");

            if (current_inode.Indirect != 0) {
                Block indirectBlock;
                disk->readDisk(disk, current_inode.Indirect, indirectBlock.Data);
                printf("    indirect block: %d\n", current_inode.Indirect);
                printf("    indirect data blocks:");
                for (u_int32_t z = 0; z < POINTERS_PER_BLOCK; z++) {
                    if (indirectBlock.Pointers[z] != 0) {
                        printf(" %u", indirectBlock.Pointers[z]);
                    }
                }
                printf("\n");
            }
        }
    }
}

// Format file system ----------------------------------------------------------
void init_fresh_super_block(Disk *disk, Block* super_block) {
    memset(super_block->Data, 0, BLOCK_SIZE);
    super_block->Super.MagicNumber = MAGIC_NUMBER;
    super_block->Super.Blocks = disk->size(disk);
    super_block->Super.InodeBlocks = (u_int32_t) ceil(super_block->Super.Blocks*0.1);
    super_block->Super.Inodes = super_block->Super.InodeBlocks * INODES_PER_BLOCK; 
}

void init_fresh_inode_block(Block* InodeBlock) {
    Inode* current_inode;
    for (int i = 0; i < INODES_PER_BLOCK; i++) {
        current_inode = InodeBlock->Inodes + i;
        current_inode->Valid=0;
        current_inode->Indirect=0;
        current_inode->Size=0;
        memset(current_inode->Direct, 0, POINTERS_PER_INODE);
    }
}

bool format(Disk *disk) {
    if (disk->mounted(disk)) return false;
    // Write superblock
    Block super_block;
    init_fresh_super_block(disk, &super_block);
    disk->writeDisk(disk, 0, super_block.Data); //prev_disk_super_block is no longer in disk
    
    // Re Init the number of needed INodes
    Block InodeBlock;
    int block_number = 1;
    for (;block_number <= super_block.Super.InodeBlocks; block_number++) {
        init_fresh_inode_block(&InodeBlock);
        disk->writeDisk(disk, block_number, InodeBlock.Data);
    }

    // Raw Data Blocks are zeroed
    Block rawBlock;
    memset(rawBlock.Data, 0, BLOCK_SIZE);
    for (;block_number < super_block.Super.Blocks; block_number++) {
        disk->writeDisk(disk, block_number, rawBlock.Data);
    }

    return true;
}

// Mount file system -----------------------------------------------------------
bool disk_fs_mount_sanity_check(Disk *disk, SuperBlock super_block) {
    int expected_inode_blocks = (int) ceil(disk->size(disk)*0.1);
    int expected_inodes = expected_inode_blocks*INODES_PER_BLOCK;
    return 
        super_block.MagicNumber == MAGIC_NUMBER &&
        super_block.Blocks == disk->size(disk) &&
        super_block.InodeBlocks == expected_inode_blocks &&
        super_block.Inodes == expected_inodes &&
        !disk->mounted(disk) &&
        !disk_registered;
}

void bootstrap_bitmap_and_inode_table(Bitmap* bitmap, InodeTable* table) {
    /**
     * Marks not available blocks in the bitmap
     * Marks not available inodes in the inode table
     */
    int inode_block_count = disk_metadata.InodeBlocks;
    Block temp_block;
    for (int i = 1; i <= inode_block_count; i++) {
        mounted_disk->readDisk(mounted_disk, i, temp_block.Data);
        bitmap->bits[i] = false;
        // Iterate over inodes in block
        for (int j = 0; j < INODES_PER_BLOCK; j++){
            Inode current_inode = temp_block.Inodes[j];
            if (!current_inode.Valid) continue; // check if Inode is valid
            // mark Inode as not available
            u_int32_t inode_number = get_inode_number_given_block_number_and_offset(i, j);
            table->entries[inode_number].available = false;
            // Iterate over direct blocks
            for (int k = 0; k < POINTERS_PER_INODE; k++) {
                u_int32_t direct_block = current_inode.Direct[k];
                if (direct_block != 0)
                    bitmap->bits[direct_block] = false;
            }
            // Iterate over indirect blocks if present
            if (current_inode.Indirect == 0) continue;
            // Bring indirect block to memory
            Block current_inode_indirect_block;
            mounted_disk->readDisk(mounted_disk, current_inode.Indirect, current_inode_indirect_block.Data);
            bitmap->bits[current_inode.Indirect] = false;
            for (int k = 0; k < POINTERS_PER_BLOCK; k++) {
                u_int32_t current_pointer = current_inode_indirect_block.Pointers[k];
                if (current_pointer != 0) 
                    bitmap->bits[current_pointer] = false;
            }
        }
    }
}

bool mount(Disk *disk) {
    Block super_block;

    if (disk_registered) return false;
    disk->readDisk(disk, 0, super_block.Data);
    
    if (!disk_fs_mount_sanity_check(disk, super_block.Super)) return false;
    
    disk->mount(disk);
    mounted_disk = disk;
    disk_registered = true;
    
    disk_metadata = super_block.Super;

    // Allocate free block bitmap
    init_bitmap(&free_blocks, disk_metadata.Blocks);
    init_inode_table(&inode_table, disk_metadata.Inodes);
    bootstrap_bitmap_and_inode_table(&free_blocks, &inode_table);
    // mark block not available

    return true;
}

// Create inode ----------------------------------------------------------------
size_t create() {
    int free_inode;
    Block inode_block_buffer;
    InodeData index;

    if (!disk_registered) return -1;
    if (!get_free_inode_number(&inode_table, &free_inode)) return -1;
    if(!load_inode(free_inode, &inode_block_buffer, &index)) return -1;
    
    inode_block_buffer.Inodes[index.offset].Valid = 1;
    inode_block_buffer.Inodes[index.offset].Size = 0;

    mounted_disk->writeDisk(mounted_disk, index.block, inode_block_buffer.Data);
    inode_table.entries[free_inode].available = false;
    return free_inode;
}

// Remove inode ----------------------------------------------------------------

bool removeInode(size_t inumber) {
    // Inode data
    Block inode_block_buffer;
    InodeData idata;
    Inode* inode;
    
    // Block for clearing out blocks
    Block temp_block;
    // Block for storing indirect block of pointers
    Block indirect_block;

    // Load inode information
    if(!load_inode(inumber, &inode_block_buffer, &idata)) return false;
    inode = idata.inode;
    if (inode->Valid == 0) return false;

    // Free direct blocks
    memset(temp_block.Data, 0, BLOCK_SIZE);
    for (int i = 0; i < POINTERS_PER_INODE; i++) {
        if (inode->Direct[i] == 0) continue;
        mounted_disk->writeDisk(mounted_disk, inode->Direct[i], temp_block.Data);
        free_blocks.bits[inode->Direct[i]] = true;
        inode->Direct[i] = 0;
    }

    // Free indirect blocks
    if (inode->Indirect!=0) {
        mounted_disk->readDisk(mounted_disk, inode->Indirect, indirect_block.Data);
        for (int i = 0; i < POINTERS_PER_BLOCK; i++) {
            if (indirect_block.Pointers[i] == 0) continue;
            mounted_disk->writeDisk(mounted_disk, indirect_block.Pointers[i], temp_block.Data);
            free_blocks.bits[indirect_block.Pointers[i]] = true;
        }
        mounted_disk->writeDisk(mounted_disk, inode->Indirect, temp_block.Data);
        free_blocks.bits[inode->Indirect] = true;
    }
    inode->Indirect = 0;

    // Clear inode in inode table
    inode->Valid = 0;
    mounted_disk->writeDisk(mounted_disk, idata.block, inode_block_buffer.Data);
    inode_table.entries[inumber].available = true;
    return true;
}

// Inode stat ------------------------------------------------------------------

size_t stat(size_t inumber) {
    // Load inode information
    InodeData idata;
    Block block_buffer;
    if (!load_inode(inumber, &block_buffer, &idata)) return -1;
    if (idata.inode->Valid == 0) return -1;
    return idata.inode->Size;
}

// Read from inode -------------------------------------------------------------
bool inode_offset_sanity_check(int start_block, int start_index_at_block) {
    return (
        start_block >= 0 &&
        start_block < POINTERS_PER_INODE + POINTERS_PER_BLOCK - 1 && // start block can be in direct blocks or in indirect blocks
        start_index_at_block >= 0 &&
        start_index_at_block < BLOCK_SIZE
    );
}



size_t readInode(size_t inumber, char *data, size_t length, size_t offset) {
    // Load inode information
    Block inode_block;
    Block indirect_block;
    Block block_buffer;
    InodeData idata;
    Inode* inode;
    int start_block;
    int start_index_at_block;
    int real_start_block;
    bool should_use_direct_blocks;
    int bytes_copied = 0;
    

    if (!load_inode(inumber, &inode_block, &idata)) return -1;
    if (idata.inode->Valid==0) return -1;
    inode = idata.inode;

    start_block = offset/BLOCK_SIZE;
    start_index_at_block = offset%BLOCK_SIZE;
    if (!inode_offset_sanity_check(start_block, start_index_at_block)) return -1;

    should_use_direct_blocks = start_block < POINTERS_PER_INODE;
    real_start_block = should_use_direct_blocks? start_block: start_block - POINTERS_PER_INODE;

    int current_block = real_start_block;
    int current_offset = start_index_at_block;
    int missing_bytes = length;

    // Read block from direct vector
    if (should_use_direct_blocks) {
        while (bytes_copied < length && current_block < POINTERS_PER_INODE) {
            if (inode->Direct[current_block] == 0) return bytes_copied; // Nothing else to read
            mounted_disk->readDisk(mounted_disk, inode->Direct[current_block], block_buffer.Data);
            int bytes_to_read = missing_bytes <= (BLOCK_SIZE-current_offset)? missing_bytes: BLOCK_SIZE-current_offset;
            memcpy(data + bytes_copied, block_buffer.Data + current_offset, bytes_to_read);
            missing_bytes -= bytes_to_read;
            bytes_copied += bytes_to_read;
            current_block++;
            current_offset = 0;
        }
        
        if (bytes_copied >= length) return bytes_copied;
    }

    // Read block from indirect vector
    if (inode->Indirect == 0) return bytes_copied;
    mounted_disk->readDisk(mounted_disk, inode->Indirect, indirect_block.Data);
    current_block = current_block%POINTERS_PER_INODE;

    while (bytes_copied < length && current_block < POINTERS_PER_BLOCK) {
        if (indirect_block.Pointers[current_block] == 0) return bytes_copied;
        mounted_disk->readDisk(mounted_disk, indirect_block.Pointers[current_block], block_buffer.Data);
        int bytes_to_read =  missing_bytes <= (BLOCK_SIZE-current_offset)? missing_bytes: BLOCK_SIZE-current_offset;
        memcpy(data + bytes_copied, block_buffer.Data + current_offset, bytes_to_read);
        missing_bytes -= bytes_to_read;
        bytes_copied += bytes_to_read;
        current_block++;
        current_offset = 0;
    }

    return bytes_copied;
}

// Write to inode --------------------------------------------------------------
int allocate_block() {
    char empty_block[BLOCK_SIZE] = {0};
    for (int i = 1 ; i < disk_metadata.Blocks; i++) {
        if (free_blocks.bits[i]) {
            free_blocks.bits[i] = false;
            mounted_disk->writeDisk(mounted_disk, i, empty_block);
            return i;
        }
    }
    return -1;
} 

void update_inode_and_save(int bytes_copied, InodeData* idata, Block* ib) {
    idata->inode->Size += bytes_copied;
    mounted_disk->writeDisk(mounted_disk, idata->block, ib->Data);
}

size_t writeInode(size_t inumber, char *data, size_t length, size_t offset) {
    // Load inode
    Block inode_block;
    Block indirect_block;
    Block block_buffer;
    InodeData idata;
    Inode* inode;
    int start_block;
    int start_index_at_block;
    int real_start_block;
    bool should_use_direct_blocks;
    int bytes_copied = 0;
    int bytes_copied_on_new_blocks = 0;
    
    if (!load_inode(inumber, &inode_block, &idata)) return -1;
    if (idata.inode->Valid==0) return -1;
    inode = idata.inode;

    start_block = offset/BLOCK_SIZE;
    start_index_at_block = offset%BLOCK_SIZE;
    if (!inode_offset_sanity_check(start_block, start_index_at_block)) return -1;

    should_use_direct_blocks = start_block < POINTERS_PER_INODE;
    real_start_block = should_use_direct_blocks? start_block: start_block - POINTERS_PER_INODE;

    int current_block = real_start_block;
    int current_offset = start_index_at_block;
    int missing_bytes = length;
    
    // Write block and copy to data
    // Read block from direct vector
    if (should_use_direct_blocks) {
        while (bytes_copied < length && current_block < POINTERS_PER_INODE) {
            bool new_block_created = false;
            if (inode->Direct[current_block] == 0) {
                int allocated_block = allocate_block();
                if (allocated_block < 0) {
                    update_inode_and_save(bytes_copied_on_new_blocks, &idata, &inode_block);
                    return bytes_copied;
                }
                new_block_created = true;
                inode->Direct[current_block] = allocated_block;
                mounted_disk->writeDisk(mounted_disk, idata.block, inode_block.Data); // Safe new inode state in disk
            } // Nothing else to read
            mounted_disk->readDisk(mounted_disk, inode->Direct[current_block], block_buffer.Data);
            int bytes_to_read = missing_bytes <= (BLOCK_SIZE-current_offset)? missing_bytes: BLOCK_SIZE-current_offset;
            memcpy(block_buffer.Data + current_offset, data + bytes_copied, bytes_to_read);
            mounted_disk->writeDisk(mounted_disk, inode->Direct[current_block], block_buffer.Data);
            if (new_block_created) bytes_copied_on_new_blocks += bytes_to_read;
            missing_bytes -= bytes_to_read;
            bytes_copied += bytes_to_read;
            current_block++;
            current_offset = 0;
        }
        
        if (bytes_copied >= length) {
            update_inode_and_save(bytes_copied_on_new_blocks, &idata, &inode_block);
            return bytes_copied;
        }
    }

    // Read block from indirect vector
    if (bytes_copied >= length) return bytes_copied;
    if (inode->Indirect == 0 && bytes_copied < length) {
        int allocated_block = allocate_block();
        if (allocated_block < 0) {
            update_inode_and_save(bytes_copied_on_new_blocks, &idata, &inode_block);
            return bytes_copied;
        }
        inode->Indirect = allocated_block;
        mounted_disk->writeDisk(mounted_disk, idata.block, inode_block.Data); // Safe new inode state in disk
    }
    mounted_disk->readDisk(mounted_disk, inode->Indirect, indirect_block.Data);
    current_block = current_block%POINTERS_PER_INODE;

    while (bytes_copied < length && current_block < POINTERS_PER_BLOCK) {
        bool new_block_created = false;
        if (indirect_block.Pointers[current_block] == 0) {
            int allocated_block = allocate_block();
            if (allocated_block < 0) {
                update_inode_and_save(bytes_copied_on_new_blocks, &idata, &inode_block);
                return bytes_copied;
            }
            indirect_block.Pointers[current_block] = allocated_block;
            mounted_disk->writeDisk(mounted_disk, inode->Indirect, indirect_block.Data);
            new_block_created = true;
        };
        mounted_disk->readDisk(mounted_disk, indirect_block.Pointers[current_block], block_buffer.Data);
        int bytes_to_read =  missing_bytes <= (BLOCK_SIZE-current_offset)? missing_bytes: BLOCK_SIZE-current_offset;

        memcpy(block_buffer.Data + current_offset, data + bytes_copied, bytes_to_read);
        mounted_disk->writeDisk(mounted_disk, indirect_block.Pointers[current_block], block_buffer.Data);

        if(new_block_created) bytes_copied_on_new_blocks += bytes_copied;

        missing_bytes -= bytes_to_read;
        bytes_copied += bytes_to_read;
        current_block++;
        current_offset = 0;
    }
    update_inode_and_save(bytes_copied_on_new_blocks, &idata, &inode_block);
    return bytes_copied;
}