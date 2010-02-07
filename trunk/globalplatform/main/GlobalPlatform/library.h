/*  Copyright (c) 2008, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GlobalPlatform is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GlobalPlatform is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with GlobalPlatform.  If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file
 * This file contains export / import / visibility definitions for functions.
*/

#ifndef OPGP_LIBRARY_H
#define OPGP_LIBRARY_H

// static library
#ifdef OPGP_LIB
	#define OPGP_API
	#define OPGP_NO_API
#else

// dynamic library
#if (defined(WIN32) || defined __CYGWIN__)
	#ifdef OPGP_EXPORTS
		#ifdef __GNUC__
		  #define OPGP_API __attribute__((dllexport))
		#else
		  #define OPGP_API __declspec(dllexport)
		#endif
	#else
		#ifdef __GNUC__
		  #define OPGP_API __attribute__((dllimport))
		#else
		  #define OPGP_API __declspec(dllimport)
		#endif
	#endif
	#define OPGP_NO_API static
#else
	#if defined __GNUC__ && (__GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
		#define OPGP_API __attribute__ ((visibility("default")))
		#define OPGP_NO_API __attribute__ ((visibility("hidden")))
	#else
		#define OPGP_API
		#define OPGP_NO_API static
	#endif
#endif // #if (defined(WIN32) || defined __CYGWIN__)

#endif // #ifdef OPGP_LIB

#if defined __GNUC__

/* GNU Compiler Collection (GCC) */
#define CONSTRUCTOR __attribute__ ((constructor))
#define DESTRUCTOR __attribute__ ((destructor))

#else

/* SUN C compiler does not use __attribute__ but #pragma init (function)
 * We can't use a # inside a #define so it is not possible to use
 * #define CONSTRUCTOR_DECLARATION(x) #pragma init (x)
 * The #pragma is used directly where needed */

/* any other */
#define CONSTRUCTOR
#define DESTRUCTOR

#endif

#endif






