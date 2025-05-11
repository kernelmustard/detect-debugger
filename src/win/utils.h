/**
 * @file utils.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief header for utility functions
 */

#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>

/**
 * @brief determine if 32- or 64-bit process
 * @return bool rval
 * @param void
 */
bool is_wow64(void);

/**
 * @brief get pointer to process env block of current process
 * @return PPEB pPEB
 * @param void
 */
PPEB get_peb(void);

#endif