/*
Mark Hoblit
hobnobber@gmail.com
http://mark.hoblit.net/crypto/
*/
/*
 *  RIPEMD-160 implementation Utility for 6502 based computers
 *
 *  Copyright (C) 2014   Mark Hoblit
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rmd160.h"

/* Program Version */
#define VERSION "1.0.0"

/* Global Variables */
int   command_undefined( char* argv[] );
int   command_rmd160( void);
int   command_test( void );
int   command_help( char* argv[] );
int   command_version( char* argv[] );
char* parameter_read( int argc, char* argv[], char* parameter );
int   parameter_exists( int argc, char* argv[], char* parameter );
FILE* parameter_set_output( int argc, char* argv[] );
FILE* parameter_set_input( int argc, char* argv[] );

static FILE *infile;
static FILE *outfile;
static int quiet;
static char *test_data[] = {
    "",
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL
};
static char *test_rmd160[] = {
    "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    "47d6f0d796f4b007d2e4d0b5411548b86588227c"
};

static unsigned char buf[1000];

/* Main function */
int main( int argc, char *argv[] )
{
    // Default return value means failure
    int return_value = 1;
    // Setup Parameters and their arguments
    infile  = parameter_set_input(argc, argv);
    outfile = parameter_set_output(argc, argv);
    quiet   = parameter_exists(argc, argv, "/q");
    // Execute command based on first parameter
    if ( !stricmp( argv[ 1 ], "/h" ) ) {
            return_value = command_rmd160();
    } else if ( !stricmp( argv[ 1 ], "/t" ) ) {
            return_value = command_test();
    } else if ( !stricmp( argv[ 1 ], "/?" ) ) {
            return_value = command_help( argv );
    } else if ( !stricmp( argv[ 1 ], "/v" ) ) {
            return_value = command_version( argv );
    } else {
            return_value = command_undefined( argv );
    }
    // Return return value from command
    return return_value;
}

/* Command undefined or invalid */
int command_undefined( char* argv[] )
{
    fprintf( stderr, "\n%s: Missing arguments.\n", argv[ 0 ] );
    if ( !quiet ) {
        fprintf( outfile, "Try '%s /?' for further\ninformation.\n", argv[ 0 ] );
    }
    return ( 1 );
}

/* Command help: displays help info */
int command_help( char* argv[] )
{
    if ( !quiet ) {
        // Usage Intro
        fprintf( outfile, "\nUsage: %s <command> [options]\n" \
               "Generate RIPEMD-160 hash of a file.\n\n", argv[ 0 ] );
        // List Commands
        fprintf( outfile, "Commands:\n");
        fprintf( outfile, " /H   Generate RIPEMD-160 hash\n" );
        fprintf( outfile, " /T   Run all tests\n" );
        fprintf( outfile, " /V   Display version info\n" );
        fprintf( outfile, " /?   Display help info\n" );
        // List Options
        fprintf( outfile, "\nOptions:\n" );
        fprintf( outfile, " /I <file> Input file\n" );
        fprintf( outfile, " /O <file> Output file\n" );
        fprintf( outfile, " /Q        Quiet mode\n" );
        // Show Notice
        fprintf( outfile, "\n%s is a simple implementation\n"
               "of the RIPEMD-160 hashing algorithm\n",argv[ 0 ] );
    }
    return ( 0 );
}

/* Command version: displays version info */
int command_version( char* argv[] )
{
    if ( !quiet ) fprintf( outfile, "\n%s %s RIPEMD-160\n" \
                    "Copyright (C) 2014 Mark Hoblit\n" \
                    "This is free software. You may\n" \
                    "redistribute copies of it under the\n" \
                    "terms of the GNU General Public\n" \
                    "License\n" \
                    "http://www.gnu.org/licenses/gpl.html\n" \
                    "There is NO WARRANTY, to the extent\n" \
                    "permitted by law.\n\n" \
                    "Written by Mark Hoblit.\n", argv[ 0 ], VERSION );
    return ( 0 );
}

/* Command test: Test RIPEMD-160 algo results */
int command_test( void )
{
    rmd160_context ctx;
    int i, j, maxtests, numsuccess = 0;
    unsigned char rmd160sum[20];
    char output[41];
    
    maxtests = sizeof( test_data ) / sizeof( test_data[0] );
    if ( !quiet ) fprintf( outfile, "\nRIPEMD-160 Validation Tests: %d\n\n",maxtests );
    for ( i = 0; i < maxtests; i++ ) {
        if ( !quiet ) fprintf( outfile, " Test %d ", i + 1 );
        rmd160_starts( &ctx );
        if ( test_data[i] != NULL ) {
            rmd160_update( &ctx, (uint8 *) test_data[i], strlen( test_data[i] ) );
        }
        else {
            memset( buf, 'a', 1000 );
            for( j = 0; j < 2; j++ ) {
                rmd160_update( &ctx, (uint8 *) buf, 1000 );
            }
        }
        rmd160_finish( &ctx, rmd160sum );
        for ( j = 0; j < 20; j++ ) sprintf( output + j * 2, "%02x", rmd160sum[j] );
        if ( memcmp( output, test_rmd160[i], 40 ) ) {
            if ( !quiet ) fprintf( outfile, "failed!\n" );
            fprintf( outfile, "exp: %s\ngot: %s\n",test_rmd160[i],output);
        }
        else {
            if ( !quiet ) fprintf( outfile, "passed.\n" );
            numsuccess ++;
        }
    }
    if ( !quiet ) fprintf ( outfile, "\nTest Results: %d of %d successful\n", numsuccess, maxtests );
    return ( numsuccess == maxtests ? 0 : 1 );
}

/* Command RIPEMD-160: Generate RIPEMD-160 hash */
int command_rmd160( void )
{
    int i, j;
    rmd160_context ctx;
    unsigned char rmd160sum[20];
    
    rmd160_starts( &ctx );
    while ( ( i = fread( buf, 1, sizeof( buf ), infile ) ) > 0 ) {
        rmd160_update( &ctx, buf, i );
    }
    rmd160_finish( &ctx, rmd160sum );
    for( j = 0; j < 20; j++ ) {
        // do not check quiet here because we always need to output the RIPEMD-160 result
        fprintf( outfile, "%02x", rmd160sum[j] );
    }
    return( 0 );
}

/* Reads parameter and returns NULL if no parameter arguments exist */
char* parameter_read( int argc, char* argv[], char* parameter )
{
    // Set return value to null
    char* return_value = NULL;
    // Loop through all parameters
    int i;
    for ( i = 1; i < argc; i++ ) {
        // Check if this is our parameter
        if ( !stricmp(argv[ i ], parameter ) && argc > i + 1 && strncmp( argv[ i + 1], "/", 1 ) ) {
            // Allocate memory
            int len = strlen( argv[ i + 1 ] );
            return_value = (char*) malloc( len + 1 );
            return_value[ len ] = '\0';
            // Copy parameter's argument
            strcpy( return_value, argv[ i + 1 ] );
            // We found parameter's argument let's exit loop ie Break
            break;
        }
    }
    return ( return_value );
}

/* Check if a parameter exists in the command line */
int parameter_exists( int argc, char* argv[], char* parameter )
{
    // Loop through parameters to see if this one was used
    int i;
    for ( i = 1; i < argc; i++ ) {
        if ( !stricmp( argv[ i ], parameter ) ) return ( 1 );
    }
    return ( 0 );
}

/* Initialize Output file based on output parameter argument */
FILE* parameter_set_output( int argc, char* argv[] )
{
    // Default Output file to stdout first
    FILE* return_value = stdout;
    // Read the parameter
    char* output_str = parameter_read( argc, argv, "/o" );
    if ( output_str != NULL ) {
        return_value = fopen( output_str, "w" );
        if ( return_value == NULL ) {
            fprintf( stderr, "%s: Cannot open output file %s\n", argv[ 0 ], output_str );
            exit ( 1 );
        }
        free( output_str );
    }
    return ( return_value );
}

/* Initialize Input file based on input parameter argument */
FILE* parameter_set_input( int argc, char* argv[] )
{
    // Default Input file to stdin first
    FILE* return_value = stdin;
    // Read the parameter
    char* input_str = parameter_read( argc, argv, "/i" );
    if ( input_str != NULL ) {
        return_value = fopen( input_str, "rb" );
        if ( return_value == NULL ) {
            fprintf( stderr, "%s: Cannot open input file %s\n", argv[ 0 ], input_str );
            exit ( 1 );
        }
        free( input_str );
    }
    return ( return_value );
}