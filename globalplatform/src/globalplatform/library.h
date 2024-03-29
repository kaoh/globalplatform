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
	#define OPGP_NO_API
#else
	#if defined __GNUC__ && (__GNUC__ >= 4)
		#define OPGP_API __attribute__ ((visibility("default")))
		#define OPGP_NO_API __attribute__ ((visibility("hidden")))
	#else
		#define OPGP_API
		#define OPGP_NO_API
	#endif
#endif // #if (defined(WIN32) || defined __CYGWIN__)

// for plugin libhraries
#if (defined(WIN32) || defined __CYGWIN__)
	#ifdef OPGP_PL_EXPORTS
		#ifdef __GNUC__
		  #define OPGP_PL_API __attribute__((dllexport))
		#else
		  #define OPGP_PL_API __declspec(dllexport)
		#endif
	#else
		#ifdef __GNUC__
		  #define OPGP_PL_API __attribute__((dllimport))
		#else
		  #define OPGP_PL_API __declspec(dllimport)
		#endif
	#endif
#else
	#if defined __GNUC__ && (__GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
		#define OPGP_PL_API __attribute__ ((visibility("default")))
	#else
		#define OPGP_PL_API
	#endif
#endif // #if (defined(WIN32) || defined __CYGWIN__)


#if defined __GNUC__

/* GNU Compiler Collection (GCC) */
#define CONSTRUCTOR __attribute__ ((constructor))
#define DESTRUCTOR __attribute__ ((destructor))

#else

#define CONSTRUCTOR
#define DESTRUCTOR

#endif

#endif






