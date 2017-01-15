# generated automatically by aclocal 1.15 -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.

# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
m4_ifndef([AC_AUTOCONF_VERSION],
  [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
m4_if(m4_defn([AC_AUTOCONF_VERSION]), [2.69],,
[m4_warning([this file was generated for autoconf 2.69.
You have another version of autoconf.  It may work, but is not guaranteed to.
If you have problems, you may need to regenerate the build system entirely.
To do so, use the procedure documented by the package, typically 'autoreconf'.])])

# Copyright (C) 2002-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
# (This private macro should not be called outside this file.)
AC_DEFUN([AM_AUTOMAKE_VERSION],
[am__api_version='1.15'
dnl Some users find AM_AUTOMAKE_VERSION and mistake it for a way to
dnl require some minimum version.  Point them to the right macro.
m4_if([$1], [1.15], [],
      [AC_FATAL([Do not call $0, use AM_INIT_AUTOMAKE([$1]).])])dnl
])

# _AM_AUTOCONF_VERSION(VERSION)
# -----------------------------
# aclocal traces this macro to find the Autoconf version.
# This is a private macro too.  Using m4_define simplifies
# the logic in aclocal, which can simply ignore this definition.
m4_define([_AM_AUTOCONF_VERSION], [])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION and AM_AUTOMAKE_VERSION so they can be traced.
# This function is AC_REQUIREd by AM_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
[AM_AUTOMAKE_VERSION([1.15])dnl
m4_ifndef([AC_AUTOCONF_VERSION],
  [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
_AM_AUTOCONF_VERSION(m4_defn([AC_AUTOCONF_VERSION]))])

# Figure out how to run the assembler.                      -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_AS
# ----------
AC_DEFUN([AM_PROG_AS],
[# By default we simply use the C compiler to build assembly code.
AC_REQUIRE([AC_PROG_CC])
test "${CCAS+set}" = set || CCAS=$CC
test "${CCASFLAGS+set}" = set || CCASFLAGS=$CFLAGS
AC_ARG_VAR([CCAS],      [assembler compiler command (defaults to CC)])
AC_ARG_VAR([CCASFLAGS], [assembler compiler flags (defaults to CFLAGS)])
_AM_IF_OPTION([no-dependencies],, [_AM_DEPENDENCIES([CCAS])])dnl
])

# AM_AUX_DIR_EXPAND                                         -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to '$srcdir/foo'.  In other projects, it is set to
# '$srcdir', '$srcdir/..', or '$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is '.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

AC_DEFUN([AM_AUX_DIR_EXPAND],
[AC_REQUIRE([AC_CONFIG_AUX_DIR_DEFAULT])dnl
# Expand $ac_aux_dir to an absolute path.
am_aux_dir=`cd "$ac_aux_dir" && pwd`
])

# AM_CONDITIONAL                                            -*- Autoconf -*-

# Copyright (C) 1997-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
AC_DEFUN([AM_CONDITIONAL],
[AC_PREREQ([2.52])dnl
 m4_if([$1], [TRUE],  [AC_FATAL([$0: invalid condition: $1])],
       [$1], [FALSE], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_SUBST([$1_TRUE])dnl
AC_SUBST([$1_FALSE])dnl
_AM_SUBST_NOTMAKE([$1_TRUE])dnl
_AM_SUBST_NOTMAKE([$1_FALSE])dnl
m4_define([_AM_COND_VALUE_$1], [$2])dnl
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi
AC_CONFIG_COMMANDS_PRE(
[if test -z "${$1_TRUE}" && test -z "${$1_FALSE}"; then
  AC_MSG_ERROR([[conditional "$1" was never defined.
Usually this means the macro was only invoked conditionally.]])
fi])])

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.


# There are a few dirty hacks below to avoid letting 'AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...


# _AM_DEPENDENCIES(NAME)
# ----------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX", "OBJC", "OBJCXX", "UPC", or "GJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

m4_if([$1], [CC],   [depcc="$CC"   am_compiler_list=],
      [$1], [CXX],  [depcc="$CXX"  am_compiler_list=],
      [$1], [OBJC], [depcc="$OBJC" am_compiler_list='gcc3 gcc'],
      [$1], [OBJCXX], [depcc="$OBJCXX" am_compiler_list='gcc3 gcc'],
      [$1], [UPC],  [depcc="$UPC"  am_compiler_list=],
      [$1], [GCJ],  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                    [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named 'D' -- because '-MD' means "put the output
  # in D".
  rm -rf conftest.dir
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir
  # We will build objects and dependencies in a subdirectory because
  # it helps to detect inapplicable dependency modes.  For instance
  # both Tru64's cc and ICC support -MD to output dependencies as a
  # side effect of compilation, but ICC will put the dependencies in
  # the current directory while Tru64 will put them in the object
  # directory.
  mkdir sub

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  am__universal=false
  m4_case([$1], [CC],
    [case " $depcc " in #(
     *\ -arch\ *\ -arch\ *) am__universal=true ;;
     esac],
    [CXX],
    [case " $depcc " in #(
     *\ -arch\ *\ -arch\ *) am__universal=true ;;
     esac])

  for depmode in $am_compiler_list; do
    # Setup a source with many dependencies, because some compilers
    # like to wrap large dependency lists on column 80 (with \), and
    # we should not choose a depcomp mode which is confused by this.
    #
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    : > sub/conftest.c
    for i in 1 2 3 4 5 6; do
      echo '#include "conftst'$i'.h"' >> sub/conftest.c
      # Using ": > sub/conftst$i.h" creates only sub/conftst1.h with
      # Solaris 10 /bin/sh.
      echo '/* dummy */' > sub/conftst$i.h
    done
    echo "${am__include} ${am__quote}sub/conftest.Po${am__quote}" > confmf

    # We check with '-c' and '-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle '-M -o', and we need to detect this.  Also, some Intel
    # versions had trouble with output in subdirs.
    am__obj=sub/conftest.${OBJEXT-o}
    am__minus_obj="-o $am__obj"
    case $depmode in
    gcc)
      # This depmode causes a compiler race in universal mode.
      test "$am__universal" = false || continue
      ;;
    nosideeffect)
      # After this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested.
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    msvc7 | msvc7msys | msvisualcpp | msvcmsys)
      # This compiler won't grok '-c -o', but also, the minuso test has
      # not run yet.  These depmodes are late enough in the game, and
      # so weak that their functioning should not be impacted.
      am__obj=conftest.${OBJEXT-o}
      am__minus_obj=
      ;;
    none) break ;;
    esac
    if depmode=$depmode \
       source=sub/conftest.c object=$am__obj \
       depfile=sub/conftest.Po tmpdepfile=sub/conftest.TPo \
       $SHELL ./depcomp $depcc -c $am__minus_obj sub/conftest.c \
         >/dev/null 2>conftest.err &&
       grep sub/conftst1.h sub/conftest.Po > /dev/null 2>&1 &&
       grep sub/conftst6.h sub/conftest.Po > /dev/null 2>&1 &&
       grep $am__obj sub/conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      # icc doesn't choke on unknown options, it will just issue warnings
      # or remarks (even with -Werror).  So we grep stderr for any message
      # that says an option was ignored or not supported.
      # When given -MP, icc 7.0 and 7.1 complain thusly:
      #   icc: Command line warning: ignoring option '-M'; no argument required
      # The diagnosis changed in icc 8.0:
      #   icc: Command line remark: option '-MP' not supported
      if (grep 'ignoring option' conftest.err ||
          grep 'not supported' conftest.err) >/dev/null 2>&1; then :; else
        am_cv_$1_dependencies_compiler_type=$depmode
        break
      fi
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
AC_SUBST([$1DEPMODE], [depmode=$am_cv_$1_dependencies_compiler_type])
AM_CONDITIONAL([am__fastdep$1], [
  test "x$enable_dependency_tracking" != xno \
  && test "$am_cv_$1_dependencies_compiler_type" = gcc3])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES.
AC_DEFUN([AM_SET_DEPDIR],
[AC_REQUIRE([AM_SET_LEADING_DOT])dnl
AC_SUBST([DEPDIR], ["${am__leading_dot}deps"])dnl
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE([dependency-tracking], [dnl
AS_HELP_STRING(
  [--enable-dependency-tracking],
  [do not reject slow dependency extractors])
AS_HELP_STRING(
  [--disable-dependency-tracking],
  [speeds up one-time build])])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
  am__nodep='_no'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
AC_SUBST([AMDEPBACKSLASH])dnl
_AM_SUBST_NOTMAKE([AMDEPBACKSLASH])dnl
AC_SUBST([am__nodep])dnl
_AM_SUBST_NOTMAKE([am__nodep])dnl
])

# Generate code to set up dependency tracking.              -*- Autoconf -*-

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.


# _AM_OUTPUT_DEPENDENCY_COMMANDS
# ------------------------------
AC_DEFUN([_AM_OUTPUT_DEPENDENCY_COMMANDS],
[{
  # Older Autoconf quotes --file arguments for eval, but not when files
  # are listed without --file.  Let's play safe and only enable the eval
  # if we detect the quoting.
  case $CONFIG_FILES in
  *\'*) eval set x "$CONFIG_FILES" ;;
  *)   set x $CONFIG_FILES ;;
  esac
  shift
  for mf
  do
    # Strip MF so we end up with the name of the file.
    mf=`echo "$mf" | sed -e 's/:.*$//'`
    # Check whether this is an Automake generated Makefile or not.
    # We used to match only the files named 'Makefile.in', but
    # some people rename them; so instead we look at the file content.
    # Grep'ing the first line is not enough: some people post-process
    # each Makefile.in and add a new line on top of each file to say so.
    # Grep'ing the whole file is not good either: AIX grep has a line
    # limit of 2048, but all sed's we know have understand at least 4000.
    if sed -n 's,^#.*generated by automake.*,X,p' "$mf" | grep X >/dev/null 2>&1; then
      dirpart=`AS_DIRNAME("$mf")`
    else
      continue
    fi
    # Extract the definition of DEPDIR, am__include, and am__quote
    # from the Makefile without running 'make'.
    DEPDIR=`sed -n 's/^DEPDIR = //p' < "$mf"`
    test -z "$DEPDIR" && continue
    am__include=`sed -n 's/^am__include = //p' < "$mf"`
    test -z "$am__include" && continue
    am__quote=`sed -n 's/^am__quote = //p' < "$mf"`
    # Find all dependency output files, they are included files with
    # $(DEPDIR) in their names.  We invoke sed twice because it is the
    # simplest approach to changing $(DEPDIR) to its actual value in the
    # expansion.
    for file in `sed -n "
      s/^$am__include $am__quote\(.*(DEPDIR).*\)$am__quote"'$/\1/p' <"$mf" | \
	 sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g'`; do
      # Make sure the directory exists.
      test -f "$dirpart/$file" && continue
      fdir=`AS_DIRNAME(["$file"])`
      AS_MKDIR_P([$dirpart/$fdir])
      # echo "creating $dirpart/$file"
      echo '# dummy' > "$dirpart/$file"
    done
  done
}
])# _AM_OUTPUT_DEPENDENCY_COMMANDS


# AM_OUTPUT_DEPENDENCY_COMMANDS
# -----------------------------
# This macro should only be invoked once -- use via AC_REQUIRE.
#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each '.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
[AC_CONFIG_COMMANDS([depfiles],
     [test x"$AMDEP_TRUE" != x"" || _AM_OUTPUT_DEPENDENCY_COMMANDS],
     [AMDEP_TRUE="$AMDEP_TRUE" ac_aux_dir="$ac_aux_dir"])
])

# Do all the work for Automake.                             -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This macro actually does too much.  Some checks are only needed if
# your package does certain things.  But this isn't really a big deal.

dnl Redefine AC_PROG_CC to automatically invoke _AM_PROG_CC_C_O.
m4_define([AC_PROG_CC],
m4_defn([AC_PROG_CC])
[_AM_PROG_CC_C_O
])

# AM_INIT_AUTOMAKE(PACKAGE, VERSION, [NO-DEFINE])
# AM_INIT_AUTOMAKE([OPTIONS])
# -----------------------------------------------
# The call with PACKAGE and VERSION arguments is the old style
# call (pre autoconf-2.50), which is being phased out.  PACKAGE
# and VERSION should now be passed to AC_INIT and removed from
# the call to AM_INIT_AUTOMAKE.
# We support both call styles for the transition.  After
# the next Automake release, Autoconf can make the AC_INIT
# arguments mandatory, and then we can depend on a new Autoconf
# release and drop the old call support.
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_PREREQ([2.65])dnl
dnl Autoconf wants to disallow AM_ names.  We explicitly allow
dnl the ones we care about.
m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl
AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
AC_REQUIRE([AC_PROG_INSTALL])dnl
if test "`cd $srcdir && pwd`" != "`pwd`"; then
  # Use -I$(srcdir) only when $(srcdir) != ., so that make's output
  # is not polluted with repeated "-I."
  AC_SUBST([am__isrc], [' -I$(srcdir)'])_AM_SUBST_NOTMAKE([am__isrc])dnl
  # test to see if srcdir already configured
  if test -f $srcdir/config.status; then
    AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
  fi
fi

# test whether we have cygpath
if test -z "$CYGPATH_W"; then
  if (cygpath --version) >/dev/null 2>/dev/null; then
    CYGPATH_W='cygpath -w'
  else
    CYGPATH_W=echo
  fi
fi
AC_SUBST([CYGPATH_W])

# Define the identity of the package.
dnl Distinguish between old-style and new-style calls.
m4_ifval([$2],
[AC_DIAGNOSE([obsolete],
             [$0: two- and three-arguments forms are deprecated.])
m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 AC_SUBST([PACKAGE], [$1])dnl
 AC_SUBST([VERSION], [$2])],
[_AM_SET_OPTIONS([$1])dnl
dnl Diagnose old-style AC_INIT with new-style AM_AUTOMAKE_INIT.
m4_if(
  m4_ifdef([AC_PACKAGE_NAME], [ok]):m4_ifdef([AC_PACKAGE_VERSION], [ok]),
  [ok:ok],,
  [m4_fatal([AC_INIT should be called with package and version arguments])])dnl
 AC_SUBST([PACKAGE], ['AC_PACKAGE_TARNAME'])dnl
 AC_SUBST([VERSION], ['AC_PACKAGE_VERSION'])])dnl

_AM_IF_OPTION([no-define],,
[AC_DEFINE_UNQUOTED([PACKAGE], ["$PACKAGE"], [Name of package])
 AC_DEFINE_UNQUOTED([VERSION], ["$VERSION"], [Version number of package])])dnl

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG([ACLOCAL], [aclocal-${am__api_version}])
AM_MISSING_PROG([AUTOCONF], [autoconf])
AM_MISSING_PROG([AUTOMAKE], [automake-${am__api_version}])
AM_MISSING_PROG([AUTOHEADER], [autoheader])
AM_MISSING_PROG([MAKEINFO], [makeinfo])
AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
AC_REQUIRE([AM_PROG_INSTALL_STRIP])dnl
AC_REQUIRE([AC_PROG_MKDIR_P])dnl
# For better backward compatibility.  To be removed once Automake 1.9.x
# dies out for good.  For more background, see:
# <http://lists.gnu.org/archive/html/automake/2012-07/msg00001.html>
# <http://lists.gnu.org/archive/html/automake/2012-07/msg00014.html>
AC_SUBST([mkdir_p], ['$(MKDIR_P)'])
# We need awk for the "check" target (and possibly the TAP driver).  The
# system "awk" is bad on some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl
AC_REQUIRE([AM_SET_LEADING_DOT])dnl
_AM_IF_OPTION([tar-ustar], [_AM_PROG_TAR([ustar])],
	      [_AM_IF_OPTION([tar-pax], [_AM_PROG_TAR([pax])],
			     [_AM_PROG_TAR([v7])])])
_AM_IF_OPTION([no-dependencies],,
[AC_PROVIDE_IFELSE([AC_PROG_CC],
		  [_AM_DEPENDENCIES([CC])],
		  [m4_define([AC_PROG_CC],
			     m4_defn([AC_PROG_CC])[_AM_DEPENDENCIES([CC])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_CXX],
		  [_AM_DEPENDENCIES([CXX])],
		  [m4_define([AC_PROG_CXX],
			     m4_defn([AC_PROG_CXX])[_AM_DEPENDENCIES([CXX])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_OBJC],
		  [_AM_DEPENDENCIES([OBJC])],
		  [m4_define([AC_PROG_OBJC],
			     m4_defn([AC_PROG_OBJC])[_AM_DEPENDENCIES([OBJC])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_OBJCXX],
		  [_AM_DEPENDENCIES([OBJCXX])],
		  [m4_define([AC_PROG_OBJCXX],
			     m4_defn([AC_PROG_OBJCXX])[_AM_DEPENDENCIES([OBJCXX])])])dnl
])
AC_REQUIRE([AM_SILENT_RULES])dnl
dnl The testsuite driver may need to know about EXEEXT, so add the
dnl 'am__EXEEXT' conditional if _AM_COMPILER_EXEEXT was seen.  This
dnl macro is hooked onto _AC_COMPILER_EXEEXT early, see below.
AC_CONFIG_COMMANDS_PRE(dnl
[m4_provide_if([_AM_COMPILER_EXEEXT],
  [AM_CONDITIONAL([am__EXEEXT], [test -n "$EXEEXT"])])])dnl

# POSIX will say in a future version that running "rm -f" with no argument
# is OK; and we want to be able to make that assumption in our Makefile
# recipes.  So use an aggressive probe to check that the usage we want is
# actually supported "in the wild" to an acceptable degree.
# See automake bug#10828.
# To make any issue more visible, cause the running configure to be aborted
# by default if the 'rm' program in use doesn't match our expectations; the
# user can still override this though.
if rm -f && rm -fr && rm -rf; then : OK; else
  cat >&2 <<'END'
Oops!

Your 'rm' program seems unable to run without file operands specified
on the command line, even when the '-f' option is present.  This is contrary
to the behaviour of most rm programs out there, and not conforming with
the upcoming POSIX standard: <http://austingroupbugs.net/view.php?id=542>

Please tell bug-automake@gnu.org about your system, including the value
of your $PATH and any error possibly output before this message.  This
can help us improve future automake versions.

END
  if test x"$ACCEPT_INFERIOR_RM_PROGRAM" = x"yes"; then
    echo 'Configuration will proceed anyway, since you have set the' >&2
    echo 'ACCEPT_INFERIOR_RM_PROGRAM variable to "yes"' >&2
    echo >&2
  else
    cat >&2 <<'END'
Aborting the configuration process, to ensure you take notice of the issue.

You can download and install GNU coreutils to get an 'rm' implementation
that behaves properly: <http://www.gnu.org/software/coreutils/>.

If you want to complete the configuration process using your problematic
'rm' anyway, export the environment variable ACCEPT_INFERIOR_RM_PROGRAM
to "yes", and re-run configure.

END
    AC_MSG_ERROR([Your 'rm' program is bad, sorry.])
  fi
fi
dnl The trailing newline in this macro's definition is deliberate, for
dnl backward compatibility and to allow trailing 'dnl'-style comments
dnl after the AM_INIT_AUTOMAKE invocation. See automake bug#16841.
])

dnl Hook into '_AC_COMPILER_EXEEXT' early to learn its expansion.  Do not
dnl add the conditional right here, as _AC_COMPILER_EXEEXT may be further
dnl mangled by Autoconf and run in a shell conditional statement.
m4_define([_AC_COMPILER_EXEEXT],
m4_defn([_AC_COMPILER_EXEEXT])[m4_provide([_AM_COMPILER_EXEEXT])])

# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  The stamp files are numbered to have different names.

# Autoconf calls _AC_AM_CONFIG_HEADER_HOOK (when defined) in the
# loop where config.status creates the headers, so we can generate
# our stamp files there.
AC_DEFUN([_AC_AM_CONFIG_HEADER_HOOK],
[# Compute $1's index in $config_headers.
_am_arg=$1
_am_stamp_count=1
for _am_header in $config_headers :; do
  case $_am_header in
    $_am_arg | $_am_arg:* )
      break ;;
    * )
      _am_stamp_count=`expr $_am_stamp_count + 1` ;;
  esac
done
echo "timestamp for $_am_arg" >`AS_DIRNAME(["$_am_arg"])`/stamp-h[]$_am_stamp_count])

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.
AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
if test x"${install_sh+set}" != xset; then
  case $am_aux_dir in
  *\ * | *\	*)
    install_sh="\${SHELL} '$am_aux_dir/install-sh'" ;;
  *)
    install_sh="\${SHELL} $am_aux_dir/install-sh"
  esac
fi
AC_SUBST([install_sh])])

# Copyright (C) 2003-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# Check whether the underlying file-system supports filenames
# with a leading dot.  For instance MS-DOS doesn't.
AC_DEFUN([AM_SET_LEADING_DOT],
[rm -rf .tst 2>/dev/null
mkdir .tst 2>/dev/null
if test -d .tst; then
  am__leading_dot=.
else
  am__leading_dot=_
fi
rmdir .tst 2>/dev/null
AC_SUBST([am__leading_dot])])

# Check to see how 'make' treats includes.	            -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
am__doit:
	@echo this is the am__doit target
.PHONY: am__doit
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include="#"
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# Ignore all kinds of additional output from 'make'.
case `$am_make -s -f confmf 2> /dev/null` in #(
*the\ am__doit\ target*)
  am__include=include
  am__quote=
  _am_result=GNU
  ;;
esac
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   case `$am_make -s -f confmf 2> /dev/null` in #(
   *the\ am__doit\ target*)
     am__include=.include
     am__quote="\""
     _am_result=BSD
     ;;
   esac
fi
AC_SUBST([am__include])
AC_SUBST([am__quote])
AC_MSG_RESULT([$_am_result])
rm -f confinc confmf
])

# Fake the existence of programs that GNU maintainers use.  -*- Autoconf -*-

# Copyright (C) 1997-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])

# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it is modern enough.
# If it is, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
AC_REQUIRE_AUX_FILE([missing])dnl
if test x"${MISSING+set}" != xset; then
  case $am_aux_dir in
  *\ * | *\	*)
    MISSING="\${SHELL} \"$am_aux_dir/missing\"" ;;
  *)
    MISSING="\${SHELL} $am_aux_dir/missing" ;;
  esac
fi
# Use eval to expand $SHELL
if eval "$MISSING --is-lightweight"; then
  am_missing_run="$MISSING "
else
  am_missing_run=
  AC_MSG_WARN(['missing' script is too old or missing])
fi
])

# Helper functions for option handling.                     -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_MANGLE_OPTION(NAME)
# -----------------------
AC_DEFUN([_AM_MANGLE_OPTION],
[[_AM_OPTION_]m4_bpatsubst($1, [[^a-zA-Z0-9_]], [_])])

# _AM_SET_OPTION(NAME)
# --------------------
# Set option NAME.  Presently that only means defining a flag for this option.
AC_DEFUN([_AM_SET_OPTION],
[m4_define(_AM_MANGLE_OPTION([$1]), [1])])

# _AM_SET_OPTIONS(OPTIONS)
# ------------------------
# OPTIONS is a space-separated list of Automake options.
AC_DEFUN([_AM_SET_OPTIONS],
[m4_foreach_w([_AM_Option], [$1], [_AM_SET_OPTION(_AM_Option)])])

# _AM_IF_OPTION(OPTION, IF-SET, [IF-NOT-SET])
# -------------------------------------------
# Execute IF-SET if OPTION is set, IF-NOT-SET otherwise.
AC_DEFUN([_AM_IF_OPTION],
[m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_PROG_CC_C_O
# ---------------
# Like AC_PROG_CC_C_O, but changed for automake.  We rewrite AC_PROG_CC
# to automatically call this.
AC_DEFUN([_AM_PROG_CC_C_O],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
AC_REQUIRE_AUX_FILE([compile])dnl
AC_LANG_PUSH([C])dnl
AC_CACHE_CHECK(
  [whether $CC understands -c and -o together],
  [am_cv_prog_cc_c_o],
  [AC_LANG_CONFTEST([AC_LANG_PROGRAM([])])
  # Make sure it works both with $CC and with simple cc.
  # Following AC_PROG_CC_C_O, we do the test twice because some
  # compilers refuse to overwrite an existing .o file with -o,
  # though they will create one.
  am_cv_prog_cc_c_o=yes
  for am_i in 1 2; do
    if AM_RUN_LOG([$CC -c conftest.$ac_ext -o conftest2.$ac_objext]) \
         && test -f conftest2.$ac_objext; then
      : OK
    else
      am_cv_prog_cc_c_o=no
      break
    fi
  done
  rm -f core conftest*
  unset am_i])
if test "$am_cv_prog_cc_c_o" != yes; then
   # Losing compiler, so override with the script.
   # FIXME: It is wrong to rewrite CC.
   # But if we don't then we get into trouble of one sort or another.
   # A longer-term fix would be to have automake use am__CC in this case,
   # and then we could set am__CC="\$(top_srcdir)/compile \$(CC)"
   CC="$am_aux_dir/compile $CC"
fi
AC_LANG_POP([C])])

# For backward compatibility.
AC_DEFUN_ONCE([AM_PROG_CC_C_O], [AC_REQUIRE([AC_PROG_CC])])

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_RUN_LOG(COMMAND)
# -------------------
# Run COMMAND, save the exit status in ac_status, and log it.
# (This has been adapted from Autoconf's _AC_RUN_LOG macro.)
AC_DEFUN([AM_RUN_LOG],
[{ echo "$as_me:$LINENO: $1" >&AS_MESSAGE_LOG_FD
   ($1) >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
   ac_status=$?
   echo "$as_me:$LINENO: \$? = $ac_status" >&AS_MESSAGE_LOG_FD
   (exit $ac_status); }])

# Check to make sure that the build environment is sane.    -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Reject unsafe characters in $srcdir or the absolute working directory
# name.  Accept space and tab only in the latter.
am_lf='
'
case `pwd` in
  *[[\\\"\#\$\&\'\`$am_lf]]*)
    AC_MSG_ERROR([unsafe absolute working directory name]);;
esac
case $srcdir in
  *[[\\\"\#\$\&\'\`$am_lf\ \	]]*)
    AC_MSG_ERROR([unsafe srcdir value: '$srcdir']);;
esac

# Do 'set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   am_has_slept=no
   for am_try in 1 2; do
     echo "timestamp, slept: $am_has_slept" > conftest.file
     set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
     if test "$[*]" = "X"; then
	# -L didn't work.
	set X `ls -t "$srcdir/configure" conftest.file`
     fi
     if test "$[*]" != "X $srcdir/configure conftest.file" \
	&& test "$[*]" != "X conftest.file $srcdir/configure"; then

	# If neither matched, then we have a broken ls.  This can happen
	# if, for instance, CONFIG_SHELL is bash and it inherits a
	# broken ls alias from the environment.  This has actually
	# happened.  Such a system could not be considered "sane".
	AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
  alias in your environment])
     fi
     if test "$[2]" = conftest.file || test $am_try -eq 2; then
       break
     fi
     # Just in case.
     sleep 1
     am_has_slept=yes
   done
   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT([yes])
# If we didn't sleep, we still need to ensure time stamps of config.status and
# generated files are strictly newer.
am_sleep_pid=
if grep 'slept: no' conftest.file >/dev/null 2>&1; then
  ( sleep 1 ) &
  am_sleep_pid=$!
fi
AC_CONFIG_COMMANDS_PRE(
  [AC_MSG_CHECKING([that generated files are newer than configure])
   if test -n "$am_sleep_pid"; then
     # Hide warnings about reused PIDs.
     wait $am_sleep_pid 2>/dev/null
   fi
   AC_MSG_RESULT([done])])
rm -f conftest.file
])

# Copyright (C) 2009-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_SILENT_RULES([DEFAULT])
# --------------------------
# Enable less verbose build rules; with the default set to DEFAULT
# ("yes" being less verbose, "no" or empty being verbose).
AC_DEFUN([AM_SILENT_RULES],
[AC_ARG_ENABLE([silent-rules], [dnl
AS_HELP_STRING(
  [--enable-silent-rules],
  [less verbose build output (undo: "make V=1")])
AS_HELP_STRING(
  [--disable-silent-rules],
  [verbose build output (undo: "make V=0")])dnl
])
case $enable_silent_rules in @%:@ (((
  yes) AM_DEFAULT_VERBOSITY=0;;
   no) AM_DEFAULT_VERBOSITY=1;;
    *) AM_DEFAULT_VERBOSITY=m4_if([$1], [yes], [0], [1]);;
esac
dnl
dnl A few 'make' implementations (e.g., NonStop OS and NextStep)
dnl do not support nested variable expansions.
dnl See automake bug#9928 and bug#10237.
am_make=${MAKE-make}
AC_CACHE_CHECK([whether $am_make supports nested variables],
   [am_cv_make_support_nested_variables],
   [if AS_ECHO([['TRUE=$(BAR$(V))
BAR0=false
BAR1=true
V=1
am__doit:
	@$(TRUE)
.PHONY: am__doit']]) | $am_make -f - >/dev/null 2>&1; then
  am_cv_make_support_nested_variables=yes
else
  am_cv_make_support_nested_variables=no
fi])
if test $am_cv_make_support_nested_variables = yes; then
  dnl Using '$V' instead of '$(V)' breaks IRIX make.
  AM_V='$(V)'
  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
else
  AM_V=$AM_DEFAULT_VERBOSITY
  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
fi
AC_SUBST([AM_V])dnl
AM_SUBST_NOTMAKE([AM_V])dnl
AC_SUBST([AM_DEFAULT_V])dnl
AM_SUBST_NOTMAKE([AM_DEFAULT_V])dnl
AC_SUBST([AM_DEFAULT_VERBOSITY])dnl
AM_BACKSLASH='\'
AC_SUBST([AM_BACKSLASH])dnl
_AM_SUBST_NOTMAKE([AM_BACKSLASH])dnl
])

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_INSTALL_STRIP
# ---------------------
# One issue with vendor 'install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in "make install-strip", and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
# Installed binaries are usually stripped using 'strip' when the user
# run "make install-strip".  However 'strip' might not be the right
# tool to use in cross-compilation environments, therefore Automake
# will honor the 'STRIP' environment variable to overrule this program.
dnl Don't test for $cross_compiling = yes, because it might be 'maybe'.
if test "$cross_compiling" != no; then
  AC_CHECK_TOOL([STRIP], [strip], :)
fi
INSTALL_STRIP_PROGRAM="\$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

# Copyright (C) 2006-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_SUBST_NOTMAKE(VARIABLE)
# ---------------------------
# Prevent Automake from outputting VARIABLE = @VARIABLE@ in Makefile.in.
# This macro is traced by Automake.
AC_DEFUN([_AM_SUBST_NOTMAKE])

# AM_SUBST_NOTMAKE(VARIABLE)
# --------------------------
# Public sister of _AM_SUBST_NOTMAKE.
AC_DEFUN([AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE($@)])

# Check how to create a tarball.                            -*- Autoconf -*-

# Copyright (C) 2004-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_PROG_TAR(FORMAT)
# --------------------
# Check how to create a tarball in format FORMAT.
# FORMAT should be one of 'v7', 'ustar', or 'pax'.
#
# Substitute a variable $(am__tar) that is a command
# writing to stdout a FORMAT-tarball containing the directory
# $tardir.
#     tardir=directory && $(am__tar) > result.tar
#
# Substitute a variable $(am__untar) that extract such
# a tarball read from stdin.
#     $(am__untar) < result.tar
#
AC_DEFUN([_AM_PROG_TAR],
[# Always define AMTAR for backward compatibility.  Yes, it's still used
# in the wild :-(  We should find a proper way to deprecate it ...
AC_SUBST([AMTAR], ['$${TAR-tar}'])

# We'll loop over all known methods to create a tar archive until one works.
_am_tools='gnutar m4_if([$1], [ustar], [plaintar]) pax cpio none'

m4_if([$1], [v7],
  [am__tar='$${TAR-tar} chof - "$$tardir"' am__untar='$${TAR-tar} xf -'],

  [m4_case([$1],
    [ustar],
     [# The POSIX 1988 'ustar' format is defined with fixed-size fields.
      # There is notably a 21 bits limit for the UID and the GID.  In fact,
      # the 'pax' utility can hang on bigger UID/GID (see automake bug#8343
      # and bug#13588).
      am_max_uid=2097151 # 2^21 - 1
      am_max_gid=$am_max_uid
      # The $UID and $GID variables are not portable, so we need to resort
      # to the POSIX-mandated id(1) utility.  Errors in the 'id' calls
      # below are definitely unexpected, so allow the users to see them
      # (that is, avoid stderr redirection).
      am_uid=`id -u || echo unknown`
      am_gid=`id -g || echo unknown`
      AC_MSG_CHECKING([whether UID '$am_uid' is supported by ustar format])
      if test $am_uid -le $am_max_uid; then
         AC_MSG_RESULT([yes])
      else
         AC_MSG_RESULT([no])
         _am_tools=none
      fi
      AC_MSG_CHECKING([whether GID '$am_gid' is supported by ustar format])
      if test $am_gid -le $am_max_gid; then
         AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        _am_tools=none
      fi],

  [pax],
    [],

  [m4_fatal([Unknown tar format])])

  AC_MSG_CHECKING([how to create a $1 tar archive])

  # Go ahead even if we have the value already cached.  We do so because we
  # need to set the values for the 'am__tar' and 'am__untar' variables.
  _am_tools=${am_cv_prog_tar_$1-$_am_tools}

  for _am_tool in $_am_tools; do
    case $_am_tool in
    gnutar)
      for _am_tar in tar gnutar gtar; do
        AM_RUN_LOG([$_am_tar --version]) && break
      done
      am__tar="$_am_tar --format=m4_if([$1], [pax], [posix], [$1]) -chf - "'"$$tardir"'
      am__tar_="$_am_tar --format=m4_if([$1], [pax], [posix], [$1]) -chf - "'"$tardir"'
      am__untar="$_am_tar -xf -"
      ;;
    plaintar)
      # Must skip GNU tar: if it does not support --format= it doesn't create
      # ustar tarball either.
      (tar --version) >/dev/null 2>&1 && continue
      am__tar='tar chf - "$$tardir"'
      am__tar_='tar chf - "$tardir"'
      am__untar='tar xf -'
      ;;
    pax)
      am__tar='pax -L -x $1 -w "$$tardir"'
      am__tar_='pax -L -x $1 -w "$tardir"'
      am__untar='pax -r'
      ;;
    cpio)
      am__tar='find "$$tardir" -print | cpio -o -H $1 -L'
      am__tar_='find "$tardir" -print | cpio -o -H $1 -L'
      am__untar='cpio -i -H $1 -d'
      ;;
    none)
      am__tar=false
      am__tar_=false
      am__untar=false
      ;;
    esac

    # If the value was cached, stop now.  We just wanted to have am__tar
    # and am__untar set.
    test -n "${am_cv_prog_tar_$1}" && break

    # tar/untar a dummy directory, and stop if the command works.
    rm -rf conftest.dir
    mkdir conftest.dir
    echo GrepMe > conftest.dir/file
    AM_RUN_LOG([tardir=conftest.dir && eval $am__tar_ >conftest.tar])
    rm -rf conftest.dir
    if test -s conftest.tar; then
      AM_RUN_LOG([$am__untar <conftest.tar])
      AM_RUN_LOG([cat conftest.dir/file])
      grep GrepMe conftest.dir/file >/dev/null 2>&1 && break
    fi
  done
  rm -rf conftest.dir

  AC_CACHE_VAL([am_cv_prog_tar_$1], [am_cv_prog_tar_$1=$_am_tool])
  AC_MSG_RESULT([$am_cv_prog_tar_$1])])

AC_SUBST([am__tar])
AC_SUBST([am__untar])
]) # _AM_PROG_TAR

# LB_CHECK_FILE
#
# Check for file existance even when cross compiling
#
AC_DEFUN([LB_CHECK_FILE],
[AS_VAR_PUSHDEF([lb_File], [lb_cv_file_$1])dnl
AC_CACHE_CHECK([for $1], lb_File,
[if test -r "$1"; then
    AS_VAR_SET(lb_File, yes)
else
    AS_VAR_SET(lb_File, no)
fi])
AS_IF([test AS_VAR_GET(lb_File) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([lb_File])dnl
])# LB_CHECK_FILE


#
# Support XEN
#
AC_DEFUN([SET_XEN_INCLUDES],
[
XEN_INCLUDES=
LB_LINUX_CONFIG([XEN],[XEN_INCLUDES="-I$LINUX/arch/x86/include/mach-xen"],[])
LB_LINUX_CONFIG_VALUE([XEN_INTERFACE_VERSION],[XEN_INCLUDES="$XEN_INCLUDES -D__XEN_INTERFACE_VERSION__=$res"],[XEN_INCLUDES="$XEN_INCLUDES -D__XEN_INTERFACE_VERSION__=$res"])
])

#
# LB_LINUX_VERSION
#
# Set things accordingly for a linux kernel
#
AC_DEFUN([LB_LINUX_VERSION],[
KMODEXT=".ko"

MODULE_TARGET="SUBDIRS"
makerule="$PWD/build"
AC_MSG_CHECKING([for external module build support])
rm -f build/conftest.i
LB_LINUX_TRY_MAKE([],[],
	[$makerule MLNX_KERNEL_TEST=conftest.i],
	[test -s build/conftest.i],
	[
		AC_MSG_RESULT([no])
	],[
		makerule="_module_$makerule"
		MODULE_TARGET="M"
		LB_LINUX_TRY_MAKE([],[],
			[$makerule MLNX_KERNEL_TEST=conftest.i],
			[test -s build/conftest.i],
			[
				AC_MSG_RESULT([yes])
			],[
				AC_MSG_ERROR([unknown; check config.log for details])
			])
	])

AC_SUBST(MODULE_TARGET)
AC_SUBST(KMODEXT)
])

#
# LB_LINUX_RELEASE
#
# get the release version of linux
#
AC_DEFUN([LB_LINUX_RELEASE],
[LINUXRELEASE=
rm -f build/conftest.i
AC_MSG_CHECKING([for Linux release])
if test -s $LINUX_OBJ/include/$AUTOCONF_HDIR/utsrelease.h ; then
	LINUXRELEASEHEADER=$AUTOCONF_HDIR/utsrelease.h
else
	LINUXRELEASEHEADER=linux/version.h
fi
LB_LINUX_TRY_MAKE([
	#include <$LINUXRELEASEHEADER>
],[
	char *LINUXRELEASE;
	LINUXRELEASE=UTS_RELEASE;
],[
	$makerule MLNX_KERNEL_TEST=conftest.i
],[
	test -s build/conftest.i
],[
	# LINUXRELEASE="UTS_RELEASE"
	eval $(grep "LINUXRELEASE=" build/conftest.i)
],[
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not preprocess test program.  Consult config.log for details.])
])
rm -f build/conftest.i
if test x$LINUXRELEASE = x ; then
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not determine Linux release version from linux/version.h.])
fi
AC_MSG_RESULT([$LINUXRELEASE])
AC_SUBST(LINUXRELEASE)

moduledir='/lib/modules/'$LINUXRELEASE/updates/kernel
AC_SUBST(moduledir)

modulefsdir='$(moduledir)/fs/$(PACKAGE)'
AC_SUBST(modulefsdir)

modulenetdir='$(moduledir)/net/$(PACKAGE)'
AC_SUBST(modulenetdir)

# ------------ RELEASE --------------------------------
AC_MSG_CHECKING([for MLNX release])
AC_ARG_WITH([release],
	AC_HELP_STRING([--with-release=string],
		       [set the release string (default=$kvers_YYYYMMDDhhmm)]),
	[RELEASE=$withval],
	RELEASE=""
	if test -n "$DOWNSTREAM_RELEASE"; then
		RELEASE="${DOWNSTREAM_RELEASE}_"
	fi
	RELEASE="$RELEASE`echo ${LINUXRELEASE} | tr '-' '_'`_$BUILDID")
AC_MSG_RESULT($RELEASE)
AC_SUBST(RELEASE)

# check is redhat/suse kernels
AC_MSG_CHECKING([that RedHat kernel])
LB_LINUX_TRY_COMPILE([
		#include <linux/version.h>
	],[
		#ifndef RHEL_RELEASE_CODE
		#error "not redhat kernel"
		#endif
	],[
		RHEL_KERNEL="yes"
		AC_MSG_RESULT([yes])
	],[
	        AC_MSG_RESULT([no])
])

LB_LINUX_CONFIG([SUSE_KERNEL],[SUSE_KERNEL="yes"],[])

])

# LB_ARG_REPLACE_PATH(PACKAGE, PATH)
AC_DEFUN([LB_ARG_REPLACE_PATH],[
	new_configure_args=
	eval "set x $ac_configure_args"
	shift
	for arg; do
		case $arg in
			--with-[$1]=*)
				arg=--with-[$1]=[$2]
				;;
			*\'*)
				arg=$(printf %s\n ["$arg"] | \
				      sed "s/'/'\\\\\\\\''/g")
				;;
		esac
		dnl AS_VAR_APPEND([new_configure_args], [" '$arg'"])
		new_configure_args="$new_configure_args \"$arg\""
	done
	ac_configure_args=$new_configure_args
])

# this is the work-horse of the next function
AC_DEFUN([__LB_ARG_CANON_PATH], [
	[$3]=$(readlink -f $with_$2)
	LB_ARG_REPLACE_PATH([$1], $[$3])
])

# a front-end for the above function that transforms - and . in the
# PACKAGE portion of --with-PACKAGE into _ suitable for variable names
AC_DEFUN([LB_ARG_CANON_PATH], [
	__LB_ARG_CANON_PATH([$1], m4_translit([$1], [-.], [__]), [$2])
])

#
#
# LB_LINUX_PATH
#
# Find paths for linux, handling kernel-source rpms
#
AC_DEFUN([LB_LINUX_PATH],
[# prep some default values
for DEFAULT_LINUX in /lib/modules/$(uname -r)/{source,build} /usr/src/linux; do
	if readlink -q -e $DEFAULT_LINUX; then
		break
	fi
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
fi
PATHS="$PATHS $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	if readlink -q -e $DEFAULT_LINUX_OBJ; then
		break
	fi
done
AC_MSG_CHECKING([for Linux sources])
AC_ARG_WITH([linux],
	AC_HELP_STRING([--with-linux=path],
		       [set path to Linux source (default=/lib/modules/$(uname -r)/{source,build},/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux], [LINUX])
	DEFAULT_LINUX_OBJ=$LINUX],
	[LINUX=$DEFAULT_LINUX])
AC_MSG_RESULT([$LINUX])
AC_SUBST(LINUX)

# -------- check for linux --------
LB_CHECK_FILE([$LINUX],[],
	[AC_MSG_ERROR([Kernel source $LINUX could not be found.])])

# -------- linux objects (for 2.6) --
AC_MSG_CHECKING([for Linux objects dir])
AC_ARG_WITH([linux-obj],
	AC_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects dir (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux-obj], [LINUX_OBJ])],
	[LINUX_OBJ=$DEFAULT_LINUX_OBJ])

AC_MSG_RESULT([$LINUX_OBJ])
AC_SUBST(LINUX_OBJ)

# -------- check for .config --------
AC_ARG_WITH([linux-config],
	[AC_HELP_STRING([--with-linux-config=path],
			[set path to Linux .conf (default=$LINUX_OBJ/.config)])],
	[LB_ARG_CANON_PATH([linux-config], [LINUX_CONFIG])],
	[LINUX_CONFIG=$LINUX_OBJ/.config])
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AC_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.  Consult build/README.kernel-source for details.]),
	[LB_ARG_CANON_PATH([kernel-source-header], [KERNEL_SOURCE_HEADER])])

# ------------ .config exists ----------------
LB_CHECK_FILE([$LINUX_CONFIG],[],
	[AC_MSG_ERROR([Kernel config could not be found.  If you are building from a kernel-source rpm consult build/README.kernel-source])])

# ----------- make dep run? ------------------
# at 2.6.19 # $LINUX/include/linux/config.h is removed
# and at more old has only one line
# include <autoconf.h>
LB_CHECK_FILE([$LINUX_OBJ/include/generated/autoconf.h],[AUTOCONF_HDIR=generated],
        [LB_CHECK_FILE([$LINUX_OBJ/include/linux/autoconf.h],[AUTOCONF_HDIR=linux],
	[AC_MSG_ERROR([Run make config in $LINUX.])])])
        AC_SUBST(AUTOCONF_HDIR)

# ----------- kconfig.h exists ---------------
# kernel 3.1, $LINUX/include/linux/kconfig.h is added
# see kernel commit 2a11c8ea20bf850b3a2c60db8c2e7497d28aba99
LB_CHECK_FILE([$LINUX/include/linux/kconfig.h],
              [CONFIG_INCLUDE=$LINUX/include/linux/kconfig.h],
              [CONFIG_INCLUDE=$LINUX/include/$AUTOCONF_HDIR/kconfig.h])
	AC_SUBST(CONFIG_INCLUDE)

if test -e $CONFIG_INCLUDE; then
	CONFIG_INCLUDE_FLAG="-include $CONFIG_INCLUDE"
fi

# ------------ rhconfig.h includes runtime-generated bits --
# red hat kernel-source checks

# we know this exists after the check above.  if the user
# tarred up the tree and ran make dep etc. in it, then
# version.h gets overwritten with a standard linux one.
#
if (grep -q rhconfig $LINUX_OBJ/include/linux/version.h 2>/dev/null) ||
   (grep -q rhconfig $LINUX_OBJ/include/generated/uapi/linux/version.h 2>/dev/null) ; then
	# This is a clean kernel-source tree, we need to
	# enable extensive workarounds to get this to build
	# modules
	LB_CHECK_FILE([$KERNEL_SOURCE_HEADER],
		[if test $KERNEL_SOURCE_HEADER = '/boot/kernel.h' ; then
			AC_MSG_WARN([Using /boot/kernel.h from RUNNING kernel.])
			AC_MSG_WARN([If this is not what you want, use --with-kernel-source-header.])
			AC_MSG_WARN([Consult build/README.kernel-source for details.])
		fi],
		[AC_MSG_ERROR([$KERNEL_SOURCE_HEADER not found.  Consult build/README.kernel-source for details.])])
	EXTRA_KCFLAGS="-include $KERNEL_SOURCE_HEADER $EXTRA_KCFLAGS"
fi

# this is needed before we can build modules
SET_BUILD_ARCH
LB_LINUX_CROSS
LB_LINUX_VERSION
SET_XEN_INCLUDES

# --- check that we can build modules at all
AC_MSG_CHECKING([that modules can be built at all])
LB_LINUX_TRY_COMPILE([],[],[
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	AC_MSG_WARN([Consult config.log for details.])
	AC_MSG_WARN([If you are trying to build with a kernel-source rpm, consult build/README.kernel-source])
	AC_MSG_ERROR([Kernel modules cannot be built.])
])

LB_LINUX_RELEASE
]) # end of LB_LINUX_PATH

# LB_LINUX_SYMVERFILE
# SLES 9 uses a different name for this file - unsure about vanilla kernels
# around this version, but it matters for servers only.
AC_DEFUN([LB_LINUX_SYMVERFILE],
	[AC_MSG_CHECKING([name of module symbol version file])
	if grep -q Modules.symvers $LINUX/scripts/Makefile.modpost ; then
		SYMVERFILE=Modules.symvers
	else
		SYMVERFILE=Module.symvers
	fi
	AC_MSG_RESULT($SYMVERFILE)
	AC_SUBST(SYMVERFILE)
])

#
# LB_LINUX_CROSS
#
# check for cross compilation
#
AC_DEFUN([LB_LINUX_CROSS],
	[AC_MSG_CHECKING([for cross compilation])
CROSS_VARS=
case $target_vendor in
	# The K1OM architecture is an extension of the x86 architecture.
	# So, the $target_arch is x86_64.
	k1om)
		AC_MSG_RESULT([Intel(R) Xeon Phi(TM)])
		CC_TARGET_ARCH=`$CC -v 2>&1 | grep Target: | sed -e 's/Target: //'`
		if test $CC_TARGET_ARCH != x86_64-$target_vendor-linux ; then
			AC_MSG_ERROR([Cross compiler not found in PATH.])
		fi
		CROSS_VARS="ARCH=$target_vendor CROSS_COMPILE=x86_64-$target_vendor-linux-"
		CCAS=$CC
		if test x$enable_server = xyes ; then
			AC_MSG_WARN([Disabling server (not supported for x86_64-$target_vendor-linux).])
			enable_server='no'
		fi
		;;
	*)
		CROSS_VARS="CROSS_COMPILE=$CROSS_COMPILE"
		AC_MSG_RESULT([no])
		;;
esac
AC_SUBST(CROSS_VARS)
])

# these are like AC_TRY_COMPILE, but try to build modules against the
# kernel, inside the build directory

# LB_LANG_PROGRAM(C)([PROLOGUE], [BODY])
# --------------------------------------
m4_define([LB_LANG_PROGRAM],
[
#include <linux/kernel.h>
$1
int
main (void)
{
dnl Do *not* indent the following line: there may be CPP directives.
dnl Don't move the `;' right after for the same reason.
$2
  ;
  return 0;
}])

#
# LB_LINUX_COMPILE_IFELSE
#
# like AC_COMPILE_IFELSE
#
AC_DEFUN([LB_LINUX_COMPILE_IFELSE],
[m4_ifvaln([$1], [AC_LANG_CONFTEST([$1])])dnl
MAKE=${MAKE:-make}
rm -f build/conftest.o build/conftest.mod.c build/conftest.ko build/output.log
AS_IF([AC_TRY_COMMAND(cp conftest.c build && env $CROSS_VARS $MAKE -d [$2] ${LD:+"LD=$CROSS_COMPILE$LD"} CC="$CROSS_COMPILE$CC" -f $PWD/build/Makefile MLNX_LINUX_CONFIG=$LINUX_CONFIG CONFIG_CC_STACKPROTECTOR_STRONG= LINUXINCLUDE="-include $AUTOCONF_HDIR/autoconf.h $XEN_INCLUDES $EXTRA_MLNX_INCLUDE -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -Iinclude -I$LINUX/arch/$SRCARCH/include/uapi -Iarch/$SRCARCH/include/generated/uapi -I$LINUX/include -I$LINUX/include/uapi -Iinclude/generated/uapi  -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -I$LINUX/arch/$SRCARCH/include -I$LINUX/arch/$SRCARCH/include/generated -I$LINUX_OBJ/include -I$LINUX/include -I$LINUX_OBJ/include2 $CONFIG_INCLUDE_FLAG" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $CROSS_VARS $MODULE_TARGET=$PWD/build >/dev/null 2>build/output.log; [[[ $? -ne 0 ]]] && cat build/output.log 1>&2 && false || config/warning_filter.sh build/output.log) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
rm -f build/conftest.o build/conftest.mod.c build/conftest.mod.o build/conftest.ko m4_ifval([$1], [build/conftest.c conftest.c])[]dnl
])

#
# LB_LINUX_ARCH
#
# Determine the kernel's idea of the current architecture
#
AC_DEFUN([LB_LINUX_ARCH],
         [AC_MSG_CHECKING([Linux kernel architecture])
          AS_IF([rm -f $PWD/build/arch
                 make -s --no-print-directory echoarch -f $PWD/build/Makefile \
                     MLNX_LINUX_CONFIG=$LINUX_CONFIG -C $LINUX $CROSS_VARS  \
                     ARCHFILE=$PWD/build/arch && LINUX_ARCH=`cat $PWD/build/arch`],
                [AC_MSG_RESULT([$LINUX_ARCH])],
                [AC_MSG_ERROR([Could not determine the kernel architecture.])])
          rm -f build/arch])

#
# LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([LB_LINUX_TRY_COMPILE],
[LB_LINUX_COMPILE_IFELSE(
	[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules],
	[test -s build/conftest.o],
	[$3], [$4])])

#
# LB_LINUX_CONFIG
#
# check if a given config option is defined
#
AC_DEFUN([LB_LINUX_CONFIG],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1])
	LB_LINUX_TRY_COMPILE([
		#include <$AUTOCONF_HDIR/autoconf.h>
	],[
		#ifndef CONFIG_$1
		#error CONFIG_$1 not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_CONFIG_IM
#
# check if a given config option is builtin or as module
#
AC_DEFUN([LB_LINUX_CONFIG_IM],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1 in or as module])
	LB_LINUX_TRY_COMPILE([
		#include <$AUTOCONF_HDIR/autoconf.h>
	],[
		#if !(defined(CONFIG_$1) || defined(CONFIG_$1_MODULE))
		#error CONFIG_$1 and CONFIG_$1_MODULE not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_TRY_MAKE
#
# like LB_LINUX_TRY_COMPILE, but with different arguments
#
AC_DEFUN([LB_LINUX_TRY_MAKE],
	[LB_LINUX_COMPILE_IFELSE(
		[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
		[$3], [$4], [$5], [$6]
	)]
)

#
# LB_CONFIG_COMPAT_RDMA
#
AC_DEFUN([LB_CONFIG_COMPAT_RDMA],
[AC_MSG_CHECKING([whether to use Compat RDMA])
# set default
AC_ARG_WITH([o2ib],
	AC_HELP_STRING([--with-o2ib=path],
		       [build o2iblnd against path]),
	[
		case $with_o2ib in
		yes)    O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
			ENABLEO2IB=2
			;;
		no)     ENABLEO2IB=0
			;;
		*)      O2IBPATHS=$with_o2ib
			ENABLEO2IB=3
			;;
		esac
	],[
		O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		ENABLEO2IB=1
	])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([no])
else
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		if test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_fmr_pool.h \); then
			o2ib_found=true
			break
		fi
	done
	compatrdma_found=false
	if $o2ib_found; then
		if test \( -f ${O2IBPATH}/include/linux/compat-2.6.h \); then
			compatrdma_found=true
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_COMPAT_RDMA, 1, [compat rdma found])
		else
			AC_MSG_RESULT([no])
		fi
	fi
fi
])

#
# LB_CONFIG_OFED_BACKPORTS
#
# include any OFED backport headers in all compile commands
# NOTE: this does only include the backport paths, not the OFED headers
#       adding the OFED headers is done in the lnet portion
AC_DEFUN([LB_CONFIG_OFED_BACKPORTS],
[AC_MSG_CHECKING([whether to use any OFED backport headers])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([no])
else
	if ! $o2ib_found; then
		AC_MSG_RESULT([no])
		case $ENABLEO2IB in
			1) ;;
			2) AC_MSG_ERROR([kernel OpenIB gen2 headers not present]);;
			3) AC_MSG_ERROR([bad --with-o2ib path]);;
			*) AC_MSG_ERROR([internal error]);;
		esac
	else
		if ! $compatrdma_found; then
                	if test -f $O2IBPATH/config.mk; then
				. $O2IBPATH/config.mk
			elif test -f $O2IBPATH/ofed_patch.mk; then
				. $O2IBPATH/ofed_patch.mk
			fi
		fi
		if test -n "$BACKPORT_INCLUDES"; then
			OFED_BACKPORT_PATH="$O2IBPATH/${BACKPORT_INCLUDES/*\/kernel_addons/kernel_addons}/"
			EXTRA_LNET_INCLUDE="-I$OFED_BACKPORT_PATH $EXTRA_LNET_INCLUDE"
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([no])
		fi
	fi
fi
])

# LC_MODULE_LOADING
# after 2.6.28 CONFIG_KMOD is removed, and only CONFIG_MODULES remains
# so we test if request_module is implemented or not
AC_DEFUN([LC_MODULE_LOADING],
[AC_MSG_CHECKING([if kernel module loading is possible])
LB_LINUX_TRY_MAKE([
	#include <linux/kmod.h>
],[
	int myretval=ENOSYS ;
	return myretval;
],[
	$makerule MLNX_KERNEL_TEST=conftest.i
],[dnl
	grep request_module build/conftest.i |dnl
		grep -v `grep "int myretval=" build/conftest.i |dnl
			cut -d= -f2 | cut -d" "  -f1`dnl
		>/dev/null dnl
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_MODULE_LOADING_SUPPORT, 1,
		  [kernel module loading is possible])
],[
	AC_MSG_RESULT(no)
	AC_MSG_WARN([])
	AC_MSG_WARN([Kernel module loading support is highly recommended.])
	AC_MSG_WARN([])
])
])

#
# LB_PROG_LINUX
#
# linux tests
#
AC_DEFUN([LB_PROG_LINUX],
[LB_LINUX_PATH
LB_LINUX_ARCH
LB_LINUX_SYMVERFILE


LB_LINUX_CONFIG([MODULES],[],[
	AC_MSG_ERROR([module support is required to build MLNX kernel modules.])
])

LB_LINUX_CONFIG([MODVERSIONS])

LB_LINUX_CONFIG([KALLSYMS],[],[
	AC_MSG_ERROR([compat_mlnx requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

# 2.6.28
LC_MODULE_LOADING

LB_CONFIG_COMPAT_RDMA

# it's ugly to be doing anything with OFED outside of the lnet module, but
# this has to be done here so that the backports path is set before all of
# the LN_PROG_LINUX checks are done
LB_CONFIG_OFED_BACKPORTS
])

#
# LB_CHECK_SYMBOL_EXPORT
# check symbol exported or not
# $1 - symbol
# $2 - file(s) for find.
# $3 - do 'yes'
# $4 - do 'no'
#
# 2.6 based kernels - put modversion info into $LINUX_OBJ/Module.modvers
# or check
AC_DEFUN([LB_CHECK_SYMBOL_EXPORT],
[AC_MSG_CHECKING([if Linux was built with symbol $1 exported])
grep -q -E '[[[:space:]]]$1[[[:space:]]]' $LINUX_OBJ/$SYMVERFILE 2>/dev/null
rc=$?
if test $rc -ne 0; then
	export=0
	for file in $2; do
		grep -q -E "EXPORT_SYMBOL.*\($1\)" "$LINUX/$file" 2>/dev/null
		rc=$?
		if test $rc -eq 0; then
			export=1
			break;
		fi
	done
	if test $export -eq 0; then
		AC_MSG_RESULT([no])
		$4
	else
		AC_MSG_RESULT([yes])
		$3
	fi
else
	AC_MSG_RESULT([yes])
	$3
fi
])

#
# Like AC_CHECK_HEADER but checks for a kernel-space header
#
m4_define([LB_CHECK_LINUX_HEADER],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])dnl
AC_CACHE_CHECK([for $1], ac_Header,
	       [LB_LINUX_COMPILE_IFELSE([LB_LANG_PROGRAM([@%:@include <$1>])],
				  [modules],
				  [test -s build/conftest.o],
				  [AS_VAR_SET(ac_Header, [yes])],
				  [AS_VAR_SET(ac_Header, [no])])])
AS_IF([test AS_VAR_GET(ac_Header) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([ac_Header])dnl
])

#
# LB_USES_DPKG
#
# Determine if the target is a dpkg system or rpm
#
AC_DEFUN([LB_USES_DPKG],
[
AC_MSG_CHECKING([if this distro uses dpkg])
case `lsb_release -i -s 2>/dev/null` in
        Ubuntu | Debian)
                AC_MSG_RESULT([yes])
                uses_dpkg=yes
                ;;
        *)
                AC_MSG_RESULT([no])
                uses_dpkg=no
                ;;
esac
])

#
# LB_PROG_CC
#
# checks on the C compiler
#
AC_DEFUN([LB_PROG_CC],
[AC_PROG_RANLIB
AC_CHECK_TOOL(LD, ld, [no])
AC_CHECK_TOOL(OBJDUMP, objdump, [no])
AC_CHECK_TOOL(STRIP, strip, [no])

# ---------  unsigned long long sane? -------
AC_CHECK_SIZEOF(unsigned long long, 0)
echo "---> size SIZEOF $SIZEOF_unsigned_long_long"
echo "---> size SIZEOF $ac_cv_sizeof_unsigned_long_long"
if test $ac_cv_sizeof_unsigned_long_long != 8 ; then
	AC_MSG_ERROR([** we assume that sizeof(long long) == 8.])
fi

if test $target_cpu == "powerpc64"; then
	AC_MSG_WARN([set compiler with -m64])
	CFLAGS="$CFLAGS -m64"
	CC="$CC -m64"
fi
])

# LB_CONTITIONALS
#
AC_DEFUN([LB_CONDITIONALS],
[
AM_CONDITIONAL(ARCH_x86, test x$target_cpu = "xx86_64" -o x$target_cpu = "xi686")

AC_OUTPUT

cat <<_ACEOF

CC:            $CC
LD:            $LD
CFLAGS:        $CFLAGS
EXTRA_KCFLAGS: $EXTRA_KCFLAGS

Type 'make' to build kernel modules.
_ACEOF
])

#
# SET_BUILD_ARCH
#
AC_DEFUN([SET_BUILD_ARCH],
[
AC_MSG_CHECKING([for build ARCH])
SRCARCH=${ARCH:-$(uname -m)}
SRCARCH=$(echo $SRCARCH | sed -e s/i.86/x86/ \
			-e s/x86_64/x86/ \
			-e s/ppc.*/powerpc/ \
			-e 's/powerpc64/powerpc/' \
			-e s/aarch64.*/arm64/ \
			-e s/s390x/s390/)

# very old kernels had different strucure under arch dir
if [[ "X$SRCARCH" == "Xx86" ]] && ! [[ -d "$LINUX/arch/x86" ]]; then
	SRCARCH=x86_64
fi

AC_MSG_RESULT([ARCH=$ARCH, SRCARCH=$SRCARCH])
])

#
# LB_LINUX_CONFIG_VALUE
#
#  get a given config's option value
#
AC_DEFUN([LB_LINUX_CONFIG_VALUE],[
	AC_MSG_CHECKING([get value of CONFIG_$1])
	if (grep -q "^#define CONFIG_$1 " $LINUX_OBJ/include/$AUTOCONF_HDIR/autoconf.h 2>/dev/null); then
		res=$(grep "^#define CONFIG_$1 " $LINUX_OBJ/include/$AUTOCONF_HDIR/autoconf.h 2>/dev/null | cut -d' ' -f'3')
		AC_MSG_RESULT([$1 value is '$res'])
		$2
	else
		AC_MSG_RESULT([$1 in not defined in autoconf.h])
		$3
	fi
])

#
# This file defines macros used to manage and support running
# build tests in parallel.
#

#
# Prepare stuff for parralel build jobs process
#
AC_DEFUN([MLNX_PARALLEL_INIT_ONCE],
[
if [[ "X${RAN_MLNX_PARALLEL_INIT_ONCE}" != "X1" ]]; then
	MAX_JOBS=${NJOBS:-1}
	RAN_MLNX_PARALLEL_INIT_ONCE=1
	/bin/rm -rf CONFDEFS_H_DIR
	/bin/mkdir -p CONFDEFS_H_DIR
	declare -i CONFDEFS_H_INDEX=0
	declare -i RUNNING_JOBS=0
fi
])

#
# MLNX_AC_DEFINE(VARIABLE, [VALUE], [DESCRIPTION])
# -------------------------------------------
# Set VARIABLE to VALUE, verbatim, or 1.  Remember the value
# and if VARIABLE is affected the same VALUE, do nothing, else
# die.  The third argument is used by autoheader.
m4_define([MLNX_AC_DEFINE], [_MLNX_AC_DEFINE_Q([\], $@)])


# _MLNX_AC_DEFINE_Q(QUOTE, VARIABLE, [VALUE], [DESCRIPTION])
# -----------------------------------------------------
# Internal function that performs common elements of AC_DEFINE{,_UNQUOTED}.
#
# m4_index is roughly 5 to 8 times faster than m4_bpatsubst, so only
# use the regex when necessary.  AC_name is defined with over-quotation,
# so that we can avoid m4_defn.
m4_define([_MLNX_AC_DEFINE_Q],
[m4_pushdef([AC_name], m4_if(m4_index([$2], [(]), [-1], [[[$2]]],
			     [m4_bpatsubst([[[$2]]], [(.*)])]))dnl
AC_DEFINE_TRACE(AC_name)dnl
m4_cond([m4_index([$3], [
])], [-1], [],
	[AS_LITERAL_IF([$3], [m4_bregexp([[$3]], [[^\\]
], [-])])], [], [],
	[m4_warn([syntax], [AC_DEFINE]m4_ifval([$1], [], [[_UNQUOTED]])dnl
[: `$3' is not a valid preprocessor define value])])dnl
m4_ifval([$4], [AH_TEMPLATE(AC_name, [$4])])dnl
cat >>CONFDEFS_H_DIR/confdefs.h.${CONFDEFS_H_INDEX} <<$1_ACEOF
[@%:@define] $2 m4_if([$#], 2, 1, [$3], [], [/**/], [$3])
_ACEOF
])

# MLNX_AC_LANG_SOURCE(C)(BODY)
# -----------------------
# We can't use '#line $LINENO "configure"' here, since
# Sun c89 (Sun WorkShop 6 update 2 C 5.3 Patch 111679-08 2002/05/09)
# rejects $LINENO greater than 32767, and some configure scripts
# are longer than 32767 lines.
m4_define([MLNX_AC_LANG_SOURCE(C)],
[/* confdefs.h.  */
_ACEOF
cat confdefs.h >>$tmpbuild/conftest.$ac_ext
cat >>$tmpbuild/conftest.$ac_ext <<_ACEOF
/* end confdefs.h.  */
$1])

# MLNX_AC_LANG_SOURCE(BODY)
# --------------------
# Produce a valid source for the current language, which includes the
# BODY, and as much as possible `confdefs.h'.
AC_DEFUN([MLNX_AC_LANG_SOURCE],
[_AC_LANG_DISPATCH([$0], _AC_LANG, $@)])


# MLNX_AC_LANG_CONFTEST(BODY)
# ----------------------
# Save the BODY in `conftest.$ac_ext'.  Add a trailing new line.
AC_DEFUN([MLNX_AC_LANG_CONFTEST],
[cat >$tmpbuild/conftest.$ac_ext <<_ACEOF
$1
_ACEOF])

# _MLNX_AC_MSG_LOG_CONFTEST
# --------------------
m4_define([_MLNX_AC_MSG_LOG_CONFTEST],
[AS_ECHO(["$as_me: failed program was:"]) >&AS_MESSAGE_LOG_FD
sed 's/^/| /' $tmpbuild/conftest.$ac_ext >&AS_MESSAGE_LOG_FD
])


#
# MLNX_LB_LINUX_COMPILE_IFELSE
#
# like AC_COMPILE_IFELSE.
# runs in a temp dir
#
AC_DEFUN([MLNX_LB_LINUX_COMPILE_IFELSE],
[
{
MAKE=${MAKE:-make}
tmpbuild=$(/bin/mktemp -d $PWD/build/build_XXXXX)
/bin/cp build/Makefile $tmpbuild/
m4_ifvaln([$1], [MLNX_AC_LANG_CONFTEST([$1])])dnl
AS_IF([AC_TRY_COMMAND(env $CROSS_VARS $MAKE -d [$2] ${LD:+"LD=$CROSS_COMPILE$LD"} CC="$CROSS_COMPILE$CC" -f $tmpbuild/Makefile MLNX_LINUX_CONFIG=$LINUX_CONFIG CONFIG_CC_STACKPROTECTOR_STRONG= LINUXINCLUDE="-include $AUTOCONF_HDIR/autoconf.h $XEN_INCLUDES $EXTRA_MLNX_INCLUDE -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -Iinclude -I$LINUX/arch/$SRCARCH/include/uapi -Iarch/$SRCARCH/include/generated/uapi -I$LINUX/include -I$LINUX/include/uapi -Iinclude/generated/uapi  -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -I$LINUX/arch/$SRCARCH/include -I$LINUX/arch/$SRCARCH/include/generated -I$LINUX_OBJ/include -I$LINUX/include -I$LINUX_OBJ/include2 $CONFIG_INCLUDE_FLAG" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $CROSS_VARS $MODULE_TARGET=$tmpbuild >/dev/null 2>$tmpbuild/output.log; [[[ $? -ne 0 ]]] && cat $tmpbuild/output.log 1>&2 && false || config/warning_filter.sh $tmpbuild/output.log) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_MLNX_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
/bin/rm -rf $tmpbuild
}
])

#
# MLNX_LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([MLNX_LB_LINUX_TRY_COMPILE],
[MLNX_LB_LINUX_COMPILE_IFELSE(
	[MLNX_AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules],
	[test -s $tmpbuild/conftest.o],
	[$3], [$4])])

# MLNX_BG_LB_LINUX_COMPILE_IFELSE
#
# Do fork and call LB_LINUX_COMPILE_IFELSE
# to run the build test in background
#
AC_DEFUN([MLNX_BG_LB_LINUX_TRY_COMPILE],
[
# init stuff
MLNX_PARALLEL_INIT_ONCE

# wait if there are MAX_JOBS tests running
if [[ $RUNNING_JOBS -eq $MAX_JOBS ]]; then
	wait
	RUNNING_JOBS=0
else
	let RUNNING_JOBS++
fi

# inc header index
let CONFDEFS_H_INDEX++

# run test in background if MAX_JOBS > 1
if [[ $MAX_JOBS -eq 1 ]]; then
MLNX_LB_LINUX_TRY_COMPILE([$1], [$2], [$3], [$4])
else
{
MLNX_LB_LINUX_TRY_COMPILE([$1], [$2], [$3], [$4])
}&
fi
])


dnl Examine kernel functionality
AC_DEFUN([LINUX_CONFIG_COMPAT],
[
	AC_MSG_CHECKING([if kernel has ktime_get_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ktime.h>
	],[
		unsigned long long ns;

		ns = ktime_get_ns();
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTIME_GET_NS, 1,
			  [ktime_get_ns defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_xprt_class has xcl_ident])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_class svc_rdma_class = {
			.xcl_ident = XPRT_TRANSPORT_RDMA,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XCL_IDENT, 1,
			  [xcl_ident defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svcxprt_rdma has sc_reader])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		struct svcxprt_rdma x = {
			.sc_reader = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVCXPRT_RDMA_SC_READER, 1,
			  [sc_reader defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_rdma.h has svc_rdma_get_write_array])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		svc_rdma_get_write_array(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_GET_WRITE_ARRAY, 1,
			  [svc_rdma_get_write_array defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has __vlan_get_protocol])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		__vlan_get_protocol(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_GET_PROTOCOL, 1,
			  [__vlan_get_protocol defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_rdma.h has svc_rdma_rcl_chunk_counts])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		svc_rdma_rcl_chunk_counts(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_RCL_CHUNK_COUNTS, 1,
			  [svc_rdma_rcl_chunk_counts defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_rdma.h has svc_rdma_get_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		svc_rdma_get_page();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_GET_PAGE, 1,
			  [svc_rdma_get_page defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has tx_rate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->max_tx_rate = 0;
		ivf->min_tx_rate = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TX_RATE_LIMIT, 1,
			  [max_tx_rate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_set_vf_tx_rate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops ndops = {
			.ndo_set_vf_tx_rate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_TX_RATE, 1,
			  [ndo_set_vf_tx_rate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has vlan_proto])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->vlan_proto = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_VLAN_PROTO, 1,
			  [vlan_proto is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_master_upper_dev_link gets 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_link(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS, 1,
			  [netdev_master_upper_dev_link gets 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rxfh])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_key_size = NULL,
			.get_rxfh = NULL,
			.set_rxfh = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH, 1,
			  [get/set_rxfh is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_rxfh_indir_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_indir_size = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RXFH_INDIR_SIZE, 1,
			[get_rxfh_indir_size is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get_rxfh_indir_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_rxfh_indir_size = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RXFH_INDIR_SIZE_EXT, 1,
			[get_rxfh_indir_size is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rxfh_indir])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>

		int mlx4_en_get_rxfh_indir(struct net_device *d, u32 *r)
		{
			return 0;
		}
	],[
		struct ethtool_ops en_ethtool_ops;
		en_ethtool_ops.get_rxfh_indir = mlx4_en_get_rxfh_indir;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH_INDIR, 1,
			[get/set_rxfh_indir is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool has set_phys_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.set_phys_id = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_PHYS_ID, 1,
			  [set_phys_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tunable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tunable = NULL,
			.set_tunable = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TUNABLE, 1,
			  [get/set_tunable is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if exist struct ethtool_ops_ext])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.size = sizeof(struct ethtool_ops_ext),
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_OPS_EXT, 1,
			  [struct ethtool_ops_ext is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get/set_rxfh_indir])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_rxfh_indir = NULL,
			.set_rxfh_indir = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH_INDIR_EXT, 1,
			  [get/set_rxfh_indir is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has __ethtool_get_link_ksettings])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		 __ethtool_get_link_ksettings(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___ETHTOOL_GET_LINK_KSETTINGS, 1,
			  [__ethtool_get_link_ksettings is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has dev_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		dev->dev_port = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_DEV_PORT, 1,
			  [dev_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has master])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev = {
			.master = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_MASTER, 1,
			  [master is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO, 1,
			  [ptp_clock_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has n_pins])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info *info;
		info->n_pins = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_N_PINS, 1,
			  [n_pins is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has gettime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.gettime = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_GETTIME_32BIT, 1,
			  [gettime 32bit is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_enable_msi_exact])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_enable_msi_exact(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_ENABLE_MSI_EXACT, 1,
			  [pci_enable_msi_exact is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_enable_msix_range])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_enable_msix_range(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_ENABLE_MSIX_RANGE, 1,
			  [pci_enable_msix_range is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_sriov_get_totalvfs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_sriov_get_totalvfs(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_SRIOV_GET_TOTALVFS, 1,
			[pci_sriov_get_totalvfs is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_msix_vec_count])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_msix_vec_count(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_MSIX_VEC_COUNT, 1,
			  [pci_msix_vec_count is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct iscsi_transport has attr_is_visible])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_iscsi.h>
	],[
		static struct iscsi_transport iscsi_iser_transport = {
			.attr_is_visible = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_ATTR_IS_VISIBLE, 1,
			  [attr_is_visible is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct iscsi_transport has get_ep_param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_iscsi.h>
	],[
		static struct iscsi_transport iscsi_iser_transport = {
			.get_ep_param = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_GET_EP_PARAM, 1,
			  [get_ep_param is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct iscsi_transport has check_protection])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_iscsi.h>
	],[
		static struct iscsi_transport iscsi_iser_transport = {
			.check_protection = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CHECK_PROTECTION, 1,
			  [check_protection is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_proto.h has struct iscsi_scsi_req])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/iscsi_proto.h>
	],[
		struct iscsi_scsi_req req = {
			.opcode = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_SCSI_REQ, 1,
			  [struct iscsi_scsi_req is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct request_queue has request_fn_active])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct request_queue rq = {
			.request_fn_active = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_QUEUE_REQUEST_FN_ACTIVE, 1,
			  [struct request_queue has request_fn_active])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has select_queue_fallback_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		select_queue_fallback_t fallback;

		fallback = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SELECT_QUEUE_FALLBACK_T, 1,
			  [select_queue_fallback_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_frag_struct has page.p])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct skb_frag_struct x;
		x.page.p = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FRAG_STRUCT_PAGE_P, 1,
			  [skb_frag_struct has page.p])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_set_hash])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_set_hash(NULL, 0, PKT_HASH_TYPE_L3);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_SET_HASH, 1,
			  [skb_set_hash is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has memcpy_to_msg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		memcpy_to_msg(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MEMCPY_TO_MSG, 1,
			  [skb_set_hash is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_pull_inline])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff skb;
		skb_pull_inline(&skb, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_PULL_INLINE, 1,
			  [skb_pull_inline is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sockios.h has SIOCGHWTSTAMP])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sockios.h>
	],[
		int x = SIOCGHWTSTAMP;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SIOCGHWTSTAMP, 1,
			  [SIOCGHWTSTAMP is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ip.h inet_get_local_port_range has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ip.h>
	],[
		inet_get_local_port_range(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_GET_LOCAL_PORT_RANGE_3_PARAMS, 1,
			  [inet_get_local_port_range has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net.h has net_get_random_once])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
	],[
		net_get_random_once(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_GET_RANDOM_ONCE, 1,
			  [net_get_random_once is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net.h sendmsg has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>

		int rds_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
				size_t payload_len)
		{
			return 0;
		}
	],[
		static const struct proto_ops rds_proto_ops = {
			.sendmsg = rds_sendmsg,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_SENDMSG_4_PARAMS, 1,
			  [sendmsg has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net.h sock_wake_async takes socket_wq])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
	],[
		struct socket_wq sk_wq;
		sock_wake_async(&sk_wq, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SOCK_WAKE_ASYNC_TAKES_SOCKET_WQ, 1,
			  [sock_wake_async takes socket_wq])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if inet_sock.h has __inet_ehashfn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/inet_sock.h>
	],[
		__inet_ehashfn(0, 0, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_EHASHFN, 1,
			  [__inet_ehashfn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if inet_sock has inet_num])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/inet_sock.h>
	],[

		struct sock *sk;
		if (inet_sk(sk)->inet_num)
			return 0;

		return 1;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_SOCK_INET_NUM, 1,
			  [inet_num is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if err.h has PTR_ERR_OR_ZERO])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/err.h>
	],[
		int x = PTR_ERR_OR_ZERO(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTR_ERR_OR_ZERO, 1,
			  [PTR_ERR_OR_ZERO is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has enum pcie_link_width])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pcie_link_width width = PCIE_LNK_WIDTH_UNKNOWN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCIE_LINK_WIDTH, 1,
			  [pcie_link_width is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has enum pci_bus_speed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pci_bus_speed speed = PCI_SPEED_UNKNOWN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_BUS_SPEED, 1,
			  [pci_bus_speed is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has linkstate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *x;
		x->linkstate = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINKSTATE, 1,
			  [linkstate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h enum pci_dev_flags has PCI_DEV_FLAGS_ASSIGNED])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pci_dev_flags x = PCI_DEV_FLAGS_ASSIGNED;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DEV_FLAGS_ASSIGNED, 1,
			  [PCI_DEV_FLAGS_ASSIGNED is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if busy_poll.h has skb_mark_napi_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/busy_poll.h>
	],[
		skb_mark_napi_id(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_MARK_NAPI_ID, 1,
			  [skb_mark_napi_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_hash_add])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_hash_add(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_HASH_ADD, 1,
			  [napi_hash_add is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has dev_consume_skb_any])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_consume_skb_any(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_CONSUME_SKB_ANY, 1,
			  [dev_consume_skb_any is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_txq_bql_complete_prefetchw])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_txq_bql_complete_prefetchw(NULL);
		netdev_txq_bql_enqueue_prefetchw(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_TXQ_BQL_PREFETCHW, 1,
			  [netdev_txq_bql_complete_prefetchw is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has xmit_more])
	case $LINUXRELEASE in
	3\.1[[0-7]]*fbk*|2*fbk*)
	AC_MSG_RESULT(Not checking xmit_more support for fbk kernel: $LINUXRELEASE)
	;;
	*)
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->xmit_more = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_XMIT_MORE, 1,
			  [xmit_more is defined])
	],[
		AC_MSG_RESULT(no)
	])
	;;
	esac

	AC_MSG_CHECKING([if struct sk_buff has encapsulation])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->encapsulation = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_ENCAPSULATION, 1,
			  [encapsulation is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has head_frag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->head_frag = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_HEAD_FRAG, 1,
			  [head_frag is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has eth_get_headlen])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_GET_HEADLEN, 1,
			  [eth_get_headlen is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has csum_level])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->csum_level = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_CSUM_LEVEL, 1,
			  [csum_level is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has skb_inner_transport_header])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_inner_transport_header(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_INNER_TRANSPORT_HEADER, 1,
			  [skb_inner_transport_header is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has skb_inner_network_header])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_inner_network_header(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_INNER_NETWORK_HEADER, 1,
			  [skb_inner_network_header is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_dev_get_egress_qos_mask])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_dev_get_egress_qos_mask(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_DEV_GET_EGRESS_QOS_MASK, 1,
			  [vlan_dev_get_egress_qos_mask is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_get_prio_tc_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_get_prio_tc_map(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_GET_PRIO_TC_MAP, 1,
			  [netdev_get_prio_tc_map is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_set_prio_tc_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_set_prio_tc_map(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_SET_PRIO_TC_MAP, 1,
			  [netdev_set_prio_tc_map is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_reset_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_reset_tc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RESET_TC, 1,
			  [netdev_reset_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_set_num_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_set_num_tc(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_SET_NUM_TC, 1,
			  [netdev_set_num_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_get_num_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_get_num_tc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_GET_NUM_TC, 1,
			  [netdev_get_num_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_set_tc_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_set_tc_queue(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_SET_TC_QUEUE, 1,
			  [netdev_set_tc_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_rx_handler_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_rx_handler_register(NULL, NULL, NULL);
		struct net_device x = {
			.rx_handler_data = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RX_HANDLER_REGISTER, 1,
			  [netdev_rx_handler_register is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h net_device_ops has ndo_set_multicast_list])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

	],[
		struct net_device_ops ndops = {
			.ndo_set_multicast_list = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_MULTICAST_LIST, 1,
			  [ndo_set_multicast_list exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_select_queue exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

	],[
		struct net_device_ops ndops = {
			.ndo_select_queue = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SELECT_QUEUE, 1,
			  [ndo_select_queue exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_select_queue has accel_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
				        void *accel_priv)
		{
			return 0;
		}
	],[
		struct net_device_ops ndops = {
			.ndo_select_queue = select_queue,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_SELECT_QUEUE_HAS_ACCEL_PRIV, 1,
			  [ndo_select_queue has accel_priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if setapp returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_setapp(struct net_device *netdev, u8 idtype,
						u16 id, u8 up)
		{
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.setapp		= mlx4_en_dcbnl_setapp,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_SETAPP_RETURNS_INT, 1,
			  [if setapp returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if getapp returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_getapp(struct net_device *netdev, u8 idtype,
						u16 id)
		{
			return 0;
		}
	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.getapp		= mlx4_en_dcbnl_getapp,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_GETAPP_RETURNS_INT, 1,
			  [if getapp returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if getnumtcs returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)

		{
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.getnumtcs	= mlx4_en_dcbnl_getnumtcs,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_GETNUMTCS_RETURNS_INT, 1,
			  [if getnumtcs returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/bonding.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/bonding.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BONDING_H, 1,
			  [include/net/bonding.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has ether_addr_copy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		ether_addr_copy(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHER_ADDR_COPY, 1,
			  [ether_addr_copy is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h enum netdev_queue_state_t has __QUEUE_STATE_XOFF])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		enum netdev_queue_state_t x = __QUEUE_STATE_XOFF;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEVICE__QUEUE_STATE_XOFF, 1,
			  [__QUEUE_STATE_XOFF is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_add_slave])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops = {
			.ndo_add_slave = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_ADD_SLAVE, 1,
			  [ndo_add_slave is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_extended has hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->hw_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_HW_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_update_features exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_update_features(dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_UPDATE_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_extended has wanted_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->wanted_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_WANTED_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_extended has _tx_ext])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->_tx_ext = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_EXTENDED_TX_EXT, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_extended has ndo_busy_poll])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int busy_poll(struct napi_struct *napi)
		{
			return 0;
		}
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->ndo_busy_poll = busy_poll;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_NDO_BUSY_POLL, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has set_netdev_hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		set_netdev_hw_features(dev, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_NETDEV_HW_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_set_xps_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netif_set_xps_queue(dev, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_XPS_QUEUE, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_features = NULL;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_FEATURES, 1,
			  [ndo_set_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_tx_maxrate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_set_tx_maxrate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_TX_MAXRATE, 1,
			  [ndo_set_tx_maxrate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_setup_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_setup_tc = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SETUP_TC, 1,
			  [ndo_setup_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_setup_tc takes 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int mlx4_en_setup_tc(struct net_device *dev, u32 handle,
							 __be16 protocol, struct tc_to_netdev *tc)
		{
			return 0;
		}
	],[
		struct net_device_ops x = {
			.ndo_setup_tc = mlx4_en_setup_tc,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SETUP_TC_4_PARAMS, 1,
			  [ndo_setup_tc takes 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_iflink])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_get_iflink = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_IFLINK, 1,
			  [ndo_get_iflink is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_fix_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_fix_features = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_FIX_FEATURES, 1,
			  [ndo_fix_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_rx_flow_steer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int rx_flow_steer(struct net_device *dev,
                                                     const struct sk_buff *skb,
                                                     u16 rxq_index,
                                                     u32 flow_id)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_rx_flow_steer = rx_flow_steer;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_FLOW_STEER, 1,
			  [ndo_rx_flow_steer is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has neigh_priv_len])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.neigh_priv_len = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_NEIGH_PRIV_LEN, 1,
			  [neigh_priv_len is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has unregister_netdevice_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		unregister_netdevice_queue(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNREGISTER_NETDEVICE_QUEUE, 1,
			  [unregister_netdevice_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_stats64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		struct rtnl_link_stats64* get_stats_64(struct net_device *dev,
                                                     struct rtnl_link_stats64 *storage)
		{
			struct rtnl_link_stats64 stats_64;
			return &stats_64;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_stats64 = get_stats_64;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_STATS64, 1,
			  [ndo_get_stats64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_stats_to_stats64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_stats_to_stats64(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_STATS_TO_STATS64, 1,
			[netdev_stats_to_stats64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops ndo_vlan_rx_add_vid has 3 parameters ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int vlan_rx_add_vid(struct net_device *dev,__be16 proto, u16 vid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_vlan_rx_add_vid = vlan_rx_add_vid;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS, 1,
			  [ndo_vlan_rx_add_vid has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops ndo_vlan_rx_add_vid has 2 parameters and returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int vlan_rx_add_vid(struct net_device *dev, u16 vid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops = {
			.ndo_vlan_rx_add_vid = vlan_rx_add_vid,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT, 1,
			  [ndo_vlan_rx_add_vid has 2 parameters and returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_get_phys_port_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_phys_port_id(struct net_device *dev,
				     struct netdev_phys_port_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_phys_port_id = get_phys_port_id;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NDO_GET_PHYS_PORT_ID, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops_ext exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext = {
			.size = sizeof(struct net_device_ops_ext),
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_OPS_EXT, 1,
			  [struct net_device_ops_ext is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_get_phys_port_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_phys_port_id(struct net_device *dev,
				     struct netdev_phys_port_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_get_phys_port_id = get_phys_port_id;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID, 1,
			  [ndo_get_phys_port_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_spoofchk = set_vf_spoofchk;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_SPOOFCHK, 1,
			  [ndo_set_vf_spoofchk is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_trust])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_trust(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_trust = set_vf_trust;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_TRUST, 1,
			  [ndo_set_vf_trust is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_features = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES, 1,
			  [ndo_set_features is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_fix_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_fix_features = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES, 1,
			  [ndo_fix_features is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_vf_spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_vf_spoofchk = set_vf_spoofchk;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK, 1,
			  [ndo_set_vf_spoofchk is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_vf_trust])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_trust(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_vf_trust = set_vf_trust;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_TRUST, 1,
			  [ndo_set_vf_trust is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_link_state])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_link_state(struct net_device *dev, int vf, int link_state)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_link_state = set_vf_link_state;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE, 1,
			  [ndo_set_vf_link_state is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_vf_link_state])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_link_state(struct net_device *dev, int vf, int link_state)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_vf_link_state = set_vf_link_state;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE, 1,
			  [ndo_set_vf_link_state is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_tx_start/stop_all_queues])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		netif_tx_start_all_queues(&dev);
		netif_tx_stop_all_queues(&dev);
		netif_tx_disable(&dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_TX_START_STOP_ALL_QUEUES, 1,
			  [netif_tx_start/stop_all_queues is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_set_real_num_tx_queues])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		netif_set_real_num_tx_queues(&dev, 2);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_REAL_NUM_TX_QUEUES, 1,
			  [netif_set_real_num_tx_queues is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdevice.h has struct xps_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct xps_map map;
		map.len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPS_MAP, 1,
			  [struct xps_map is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool_ext has set_phys_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.set_phys_id = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_PHYS_ID_EXT, 1,
			  [set_phys_id is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_channels])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_channels = NULL,
			.set_channels = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_CHANNELS, 1,
			  [get/set_channels is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_priv_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_priv_flags = NULL,
			.set_priv_flags = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_PRIV_FLAGS, 1,
			  [get/set_priv_flags is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get/set_channels])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_channels = NULL,
			.set_channels = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_CHANNELS_EXT, 1,
			  [get/set_channels is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_flags = NULL,
			.set_flags = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_FLAGS, 1,
			  [get/set_flags is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tso])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tso = NULL,
			.set_tso = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TSO, 1,
			  [get/set_tso is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_sg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_sg = NULL,
			.set_sg = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_SG, 1,
			  [get/set_sg is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tx_csum])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tx_csum = NULL,
			.set_tx_csum = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TX_CSUM, 1,
			  [get/set_tx_csum is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rx_csum])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rx_csum = NULL,
			.set_rx_csum = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RX_CSUM, 1,
			  [get/set_rx_csum is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has ethtool_op_set_flags gets 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		ethtool_op_set_flags(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_OP_SET_FLAGS_2_PARAMS, 1,
			  [ethtool_op_set_flags gets 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_ts_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_ts_info = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_TS_INFO, 1,
			  [get_ts_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get_ts_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_ts_info = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_TS_INFO_EXT, 1,
			  [get_ts_info is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_flow_ext has h_dest])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		unsigned char mac[ETH_ALEN];
		struct ethtool_flow_ext h_ext;

		memcpy(&mac, h_ext.h_dest, ETH_ALEN);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_FLOW_EXT_H_DEST, 1,
			  [ethtool_flow_ext has h_dest])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops get_rxnfc gets u32 *rule_locs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
		static int mlx4_en_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *c,
					     u32 *rule_locs)
		{
			return 0;
		}
	],[
		struct ethtool_ops x = {
			.get_rxnfc = mlx4_en_get_rxnfc,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_OPS_GET_RXNFC_U32_RULE_LOCS, 1,
			  [ethtool_ops get_rxnfc gets u32 *rule_locs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_vfs_assigned])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev pdev;
		pci_vfs_assigned(&pdev);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_VFS_ASSIGNED, 1,
			  [pci_vfs_assigned is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h struct pci_driver has sriov_configure])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_driver x = {
			.sriov_configure = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DRIVER_SRIOV_CONFIGURE, 1,
			  [pci_driver sriov_configure is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __vlan_hwaccel_put_tag has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		struct sk_buff *skb;
		__vlan_hwaccel_put_tag(skb, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_3_PARAMS_FOR_VLAN_HWACCEL_PUT_TAG, 1,
			  [__vlan_hwaccel_put_tag has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.hw_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HW_FEATURES, 1,
			  [hw_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has wanted_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.wanted_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_WANTED_FEATURES, 1,
			  [wanted_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_features_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_features_check(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_FEATURES_CHECK, 1,
			  [vlan_features_check is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has hw_enc_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.hw_enc_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HW_ENC_FEATURES, 1,
			  [hw_enc_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has rx_cpu_rmap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.rx_cpu_rmap = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RX_CPU_RMAP, 1,
			  [rx_cpu_rmap is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has addr_assign_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.addr_assign_type = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_ADDR_ASSIGN_TYPE, 1,
			  [addr_assign_type is defined])
	],[
		AC_MSG_RESULT(no)
	])

	 AC_MSG_CHECKING([if etherdevice.h has eth_random_addr])
		MLNX_BG_LB_LINUX_TRY_COMPILE([
	                 #include <linux/etherdevice.h>
		],[
	                eth_random_addr(NULL);

			return 0;
		],[
			AC_MSG_RESULT(yes)
			MLNX_AC_DEFINE(HAVE_ETH_RANDOM_ADDR, 1,
				[eth_random_addr is defined in netdevice.h])
		],[
			AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has IFF_UNICAST_FLT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = IFF_UNICAST_FLT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_IFF_UNICAST_FLT, 1,
			  [IFF_UNICAST_FLT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_for_each_mc_addr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_hw_addr *ha;
		struct net_device *netdev;
		netdev_for_each_mc_addr(ha, netdev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FOR_EACH_MC_ADDR, 1,
			  [netdev_for_each_mc_addr is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if irqdesc.h has irq_desc_get_irq_data])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq.h>
		#include <linux/irqdesc.h>
	],[
		struct irq_desc desc;
		struct irq_data *data = irq_desc_get_irq_data(&desc);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_DESC_GET_IRQ_DATA, 1,
			  [irq_desc_get_irq_data is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if irq.h irq_data has member affinity])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq.h>
		#include <linux/cpumask.h>
	],[
		cpumask_var_t x;
		struct irq_data y = {
			.affinity = x,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_DATA_AFFINITY, 1,
			  [irq_data member affinity is defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if pci_dev has pcie_mpss])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev *pdev;

		pdev->pcie_mpss = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DEV_PCIE_MPSS, 1,
			  [pcie_mpss is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/if_ether.h exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if_ether.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_LINUX_IF_ETHER_H, 1,
			  [uapi/linux/if_ether.h exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ifla_vf_info has spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->spoofchk = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_INFO_SPOOFCHK, 1,
			  [spoofchk is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ifla_vf_info has trust])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->trusted = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_INFO_TRUST, 1,
			  [trust is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kthread.h has struct kthread_work])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kthread.h>
	],[
		struct kthread_work x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTHREAD_WORK, 1,
			  [struct kthread_work is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/timecounter.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_H, 1,
			  [linux/timecounter.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	# timecounter_adjtime can be in timecounter.h or clocksource.h
	AC_MSG_CHECKING([if linux/timecounter.h has timecounter_adjtime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		struct timecounter x;
		s64 y = 0;
		timecounter_adjtime(&x, y);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_ADJTIME, 1,
			  [timecounter_adjtime is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/clocksource.h has timecounter_adjtime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/clocksource.h>
	],[
		struct timecounter x;
		s64 y = 0;
		timecounter_adjtime(&x, y);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_ADJTIME, 1,
			  [timecounter_adjtime is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_schedule_irqoff])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_schedule_irqoff(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_SCHEDULE_IRQOFF, 1,
			  [napi_schedule_irqoff is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h enum ethtool_stringset has ETH_SS_RSS_HASH_FUNCS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		enum ethtool_stringset x = ETH_SS_RSS_HASH_FUNCS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_SS_RSS_HASH_FUNCS, 1,
			  [ETH_SS_RSS_HASH_FUNCS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_complete_done])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_complete_done(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_COMPLETE_DONE, 1,
			  [napi_complete_done is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_rss_key_fill])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_rss_key_fill(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RSS_KEY_FILL, 1,
			  [netdev_rss_key_fill is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has struct netdev_phys_item_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_phys_item_id x;
		x.id_len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_PHYS_ITEM_ID, 1,
			  [netdev_phys_item_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if cyclecounter_cyc2ns has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		cyclecounter_cyc2ns(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CYCLECOUNTER_CYC2NS_4_PARAMS, 1,
			  [cyclecounter_cyc2ns has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h struct net_device_ops has ndo_features_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		static const struct net_device_ops mlx4_netdev_ops = {
			.ndo_features_check	= NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FEATURES_T, 1,
			  [netdev_features_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_RXFCS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t rxfcs = NETIF_F_RXFCS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXFCS, 1,
			[NETIF_F_RXFCS is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_HW_VLAN_STAG_RX])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t stag = NETIF_F_HW_VLAN_STAG_RX;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_HW_VLAN_STAG_RX, 1,
			[NETIF_F_HW_VLAN_STAG_RX is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_RXALL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t rxfcs = NETIF_F_RXALL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXALL, 1,
			[NETIF_F_RXALL is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_IS_BOND_MASTER])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		return netif_is_bond_master(dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_BOND_MASTER, 1,
			[NETIF_IS_BOND_MASTER is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_gro_receive])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_gro_receive(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_GRO_RECEIVE, 1,
			[vlan_gro_receive is defined in if_vlan.h])
	],[
		AC_MSG_RESULT(no)
	])

       AC_MSG_CHECKING([if if_vlan.h has vlan_hwaccel_rx])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
               #include <linux/if_vlan.h>
       ],[
               vlan_hwaccel_rx(NULL, NULL, 0);

               return 0;
       ],[
               AC_MSG_RESULT(yes)
               MLNX_AC_DEFINE(HAVE_VLAN_HWACCEL_RX, 1,
                       [vlan_hwaccel_rx is defined in if_vlan.h])
       ],[
               AC_MSG_RESULT(no)
       ])

	AC_MSG_CHECKING([if vxlan has vxlan_get_rx_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#if IS_ENABLED(CONFIG_VXLAN)
		#include <net/vxlan.h>
		#endif
	],[
		vxlan_get_rx_port(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_ENABLED, 1,
			  [vxlan_get_rx_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_shared_info has UNION tx_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct skb_shared_info x;
		x.tx_flags.flags = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS, 1,
			  [skb_shared_info has union tx_flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vxlan have ndo_add_vxlan_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		#if IS_ENABLED(CONFIG_VXLAN)
		void add_vxlan_port(struct net_device *dev, sa_family_t sa_family, __be16 port)
		{
			return 0;
		}
		#endif
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_add_vxlan_port = add_vxlan_port;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_DYNAMIC_PORT, 1,
			[ndo_add_vxlan_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vxlan.h has vxlan_gso_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		vxlan_gso_check(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_GSO_CHECK, 1,
			  [vxlan_gso_check is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst.h has dst_get_neighbour])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/dst.h>
	],[
		struct neighbour *neigh = dst_get_neighbour(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DST_GET_NEIGHBOUR, 1,
			  [dst_get_neighbour is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst.h has dst_neigh_lookup])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/dst.h>
	],[
		struct neighbour *neigh = dst_neigh_lookup(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DST_NEIGH_LOOKUP, 1,
			  [dst_neigh_lookup is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_dump_control has dump])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_dump_control c = {
			.dump = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_CONTROL_DUMP, 1,
			  [netlink_dump_control dump is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_dump_control has module])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_dump_control c = {
			.module = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_CONTROL_MODULE, 1,
			  [netlink_dump_control module is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_callback has module])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_callback c = {
			.module = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_CALLBACK_MODULE, 1,
			  [netlink_callback module is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_skb_parms has sk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_skb_parms nsp = {
			.sk = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_SKB_PARMS_SK, 1,
			  [netlink_skb_params has sk])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if netlink.h has netlink_capable])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/netlink.h>
        ],[
                bool b = netlink_capable(NULL, 0);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NETLINK_CAPABLE, 1,
                          [netlink_capable is defined])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netlink.h netlink_kernel_cfg has input])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_kernel_cfg cfg = {
			.input = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_KERNEL_CFG_INPUT, 1,
			  [netlink_kernel_cfg input is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink_kernel_create has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		netlink_kernel_create(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_KERNEL_CREATE_3_PARAMS, 1,
			  [netlink_kernel_create has 3 params])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if netlink_dump_start has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		int ret = netlink_dump_start(NULL, NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_START_5P, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dcbnl_rtnl_ops has ieee_getmaxrate/ieee_setmaxrate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		const struct dcbnl_rtnl_ops en_dcbnl_ops = {
			.ieee_getmaxrate = NULL,
			.ieee_setmaxrate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_GET_SET_MAXRATE, 1,
			  [ieee_getmaxrate/ieee_setmaxrate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dcbnl.h dcbnl_rtnl_ops getnumtcs returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
		static int func1(struct net_device * a, int b, u8 * c) {
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops x = {
			.getnumtcs = func1,
		};
			return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DCBNL_RTNL_OPS_GETNUMTCS_RET_INT, 1,
 			       [getnumtcs returns int])
 	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_cmnd.h has scsi_prot_interval])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_prot_interval(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_PROT_INTERVAL, 1,
			  [scsi_prot_interval is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has get_module_eeprom])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_module_eeprom = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_MODULE_EEPROM, 1,
			  [HAVE_GET_MODULE_EEPROM is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has set_dump])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.set_dump = NULL,
			.get_dump_data = NULL,
			.get_dump_flag = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_DUMP, 1,
			[HAVE_GET_SET_DUMP is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has get_module_eeprom])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops_ext x = {
			.get_module_eeprom = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_MODULE_EEPROM_EXT, 1,
			[HAVE_GET_MODULE_EEPROM_EXT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h struct net_device has wanted_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device x = {
			.wanted_features  = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WANTED_FEATURES, 1,
			  [wanted_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h struct net_device has trans_start])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device x = {
			.trans_start  = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ND_TRANS_START, 1,
			  [trans_start is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_add_rx_frag has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_add_rx_frag(NULL, 0, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_ADD_RX_FRAG_5_PARAMS, 1,
			  [skb_add_rx_frag has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if addrconf.h has addrconf_ifid_eui48])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
	],[
		int x = addrconf_ifid_eui48(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ADDRCONF_IFID_EUI48, 1,
			  [addrconf_ifid_eui48 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has struct netdev_bonding_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_bonding_info x;
		x.master.num_slaves = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_BONDING_INFO, 1,
			  [netdev_bonding_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_xprt.h struct svc_xprt_ops has *xpo_secure_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops x = {
			.xpo_secure_port = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPO_SECURE_PORT, 1,
			  [xpo_secure_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/dcbnl.h struct dcbnl_rtnl_ops has *ieee_getqcn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		struct dcbnl_rtnl_ops x = {
			.ieee_getqcn = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_GETQCN, 1,
			  [ieee_getqcn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dcbnl.h has struct ieee_qcn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		struct ieee_qcn x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_IEEE_QCN, 1,
			  [ieee_qcn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has dev_get_by_index_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_get_by_index_rcu(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_GET_BY_INDEX_RCU, 1,
			  [dev_get_by_index_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h dev_mc_add has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_mc_add(NULL,NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_MC_ADD_2_PARAMS, 1,
			  [dev_mc_add has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_class_create_file_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_class_create_file_ns(NULL,NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_CLASS_CREATE_FILE_NS, 1,
			  [netdev_class_create_file_ns is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_upper_dev_unlink])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_upper_dev_unlink(NULL,NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_UPPER_DEV_UNLINK, 1,
			  [netdev_upper_dev_unlink is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_master_upper_dev_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_get(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_MASTER_UPPER_DEV_GET, 1,
			  [netdev_master_upper_dev_get is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_master_upper_dev_get_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_get_rcu(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU, 1,
			  [netdev_master_upper_dev_get_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_has_upper_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		struct net_device *upper;
		netdev_has_upper_dev(dev, upper);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HAS_UPPER_DEV, 1,
			  [netdev_has_upper_dev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_for_each_all_upper_dev_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		struct net_device *upper;
		struct list_head *list;

		netdev_for_each_all_upper_dev_rcu(dev, upper, list);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FOR_EACH_ALL_UPPER_DEV_RCU, 1,
			  [netdev_master_upper_dev_get_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has NETDEV_CHANGEUPPER])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int a = NETDEV_CHANGEUPPER;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_CHANGEUPPER, 1,
			  [netdev_master_upper_dev_get_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct inet6_ifaddr has member if_list])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/if_inet6.h>
	],[
		struct inet6_ifaddr x;
		struct list_head xlist;
		x.if_list = xlist;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET6_IF_LIST, 1,
			  [if_list is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has drain_workqueue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		drain_workqueue(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DRAIN_WORKQUEUE, 1,
			  [drain_workqueue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has __cancel_delayed_work])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		__cancel_delayed_work(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___CANCEL_DELAYED_WORK, 1,
			  [__cancel_delayed_work is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_UNBOUND])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_UNBOUND, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_UNBOUND, 1,
			  [WQ_UNBOUND is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_HIGHPRI])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_HIGHPRI, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_HIGHPRI, 1,
			  [WQ_HIGHPRI is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_MEM_RECLAIM])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_MEM_RECLAIM, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_MEM_RECLAIM, 1,
			  [WQ_MEM_RECLAIM is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_UNBOUND_MAX_ACTIVE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", 0, WQ_UNBOUND_MAX_ACTIVE);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_UNBOUND_MAX_ACTIVE, 1,
			  [WQ_UNBOUND_MAX_ACTIVE is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mm_struct has member pinned_vm])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
		x.pinned_vm = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PINNED_VM, 1,
			  [pinned_vm is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if proc_fs.h has proc_set_user])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
		#include <linux/uidgid.h>
	],[
		kuid_t a;
		kgid_t b;
		proc_set_user(NULL, a, b);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PROC_SET_USER, 1,
			  [proc_set_user is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/if_bonding.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if_bonding.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_IF_BONDING_H, 1,
			  [uapi/linux/if_bonding.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_xprt.h svc_xprt_init has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		svc_xprt_init(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_XPRT_INIT_4_PARAMS, 1,
			  [svc_xprt_init has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc.h struct svc_rqst has member rq_next_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_rqst x;
		x.rq_next_page = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RQ_NEXT_PAGE, 1,
			  [rq_next_page is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/sunrpc/addr.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/addr.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SUNRPC_ADDR_H, 1,
			  [linux/sunrpc/addr.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt.h struct rpc_xprt has xprt_alloc_slot])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		xprt_alloc_slot(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_ALLOC_SLOT, 1,
			  [xprt_alloc_slot is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt.h xprt_alloc has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		xprt_alloc(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_ALLOC_HAS_3_PARAMS, 1,
			  [xprt_alloc has 3 params is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt.h xprt_alloc has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		xprt_alloc(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_ALLOC_HAS_4_PARAMS, 1,
			  [xprt_alloc has 4 params is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt.h rpc_xprt_ops.connect has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>

		static void xprt_rdma_connect(struct rpc_xprt *xprt, struct rpc_task *task)
		{
			return;
		}
	],[
		struct rpc_xprt_ops x = {
			.connect = xprt_rdma_connect,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_OPS_CONNECT_2_PARAMS, 1,
			  [rpc_xprt_ops.connect has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if highmem.h kmap_atomic has 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/highmem.h>
	],[
		kmap_atomic(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KMAP_ATOMIC_1_PARAM, 1,
			  [kmap_atomic has 1 parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has atomic_long_read param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/atomic.h>
	],[
		atomic_long_read(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ATOMIC_LONG_READ, 1,
			  [atomic_long_read exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if percpu.h has __this_cpu_read])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/percpu.h>
	],[
		unsigned long count = 0;
		__this_cpu_read(count);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_THIS_CPU_READ, 1,
			  [percpu.h has __this_cpu_read])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if percpu.h has __get_cpu_var])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/percpu.h>

		DECLARE_PER_CPU(struct teststats, teststats);
		struct teststats {
			u64 count;
		};
		#define TESTSTATS_COUNTER_INC(stat) do { __get_cpu_var(teststats).stat++; } while (0)
	],[
		TESTSTATS_COUNTER_INC(count);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_CPU_VAR, 1,
			  [percpu.h has __get_cpu_var])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has sk_clone_lock])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		struct sock sk;
		sk_clone_lock(&sk, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_CLONE_LOCK, 1,
			  [sk_clone_lock is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has sk_page_frag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		struct sock x;
		sk_page_frag(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_PAGE_FRAG, 1,
			  [sk_page_frag is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h struct sock has sk_data_ready has 2 parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>

		void listen_data_ready(struct sock *sk, int len)
		{
			return;
		}
	],[
		struct sock x = {
			.sk_data_ready = listen_data_ready,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_DATA_READY_2_PARAMS, 1,
			  [sk_data_ready has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h sk_alloc has 5 parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sk_alloc(NULL, 0, GFP_KERNEL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_ALLOC_5_PARAMS, 1,
			  [sk_alloc has 5 parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h sk_wait_data has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sk_wait_data(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_WAIT_DATA_3_PARAMS, 1,
			  [sk_wait_data has 3 params])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if sk_rmem_schedule has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sk_rmem_schedule(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_RMEM_SCHEDULE_3P, 1,
			  [sk_rmem_schedule has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has skb_copy_to_page_nocache])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		skb_copy_to_page_nocache(NULL, NULL, NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_COPY_TO_PAGE_NOCACHE, 1,
			  [sock.h has skb_copy_to_page_nocache])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tcp.h has tcp_passive_fastopen])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/tcp.h>
	],[
		tcp_passive_fastopen(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCP_PASSIVE_FASTOPEN, 1,
			  [tcp.h has tcp_passive_fastopen])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h struct pci_dev has member msix_cap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev x = {
			.msix_cap = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MSIX_CAP, 1,
			  [msix_cap is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has dev_mc_del])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_mc_del(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_MC_DEL, 1,
			  [dev_mc_del is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if cpu_rmap.h has struct cpu_rmap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/cpu_rmap.h>
	],[
		struct cpu_rmap rmap;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CPU_RMAP, 1,
			  [cpu_rmap is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if proc_fs.h has PDE_DATA])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
	],[
		PDE_DATA(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PDE_DATA, 1,
			  [PDE_DATA is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if route.h struct rtable has member rt_uses_gateway])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_uses_gateway = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RT_USES_GATEWAY, 1,
			  [rt_uses_gateway is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if route.h struct rtable has member *idev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		struct rtable x = {
			.idev = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RTABLE_IDEV, 1,
			  [idev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([split_page],
		[mm/page_alloc.c],
		[AC_DEFINE(HAVE_SPLIT_PAGE_EXPORTED, 1,
			[split_page is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([irq_to_desc],
		[kernel/irq/irqdesc.c],
		[AC_DEFINE(HAVE_IRQ_TO_DESC_EXPORTED, 1,
			[irq_to_desc is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if ptp_clock_kernel.h ptp_clock_register has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		ptp_clock_register(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_REGISTER_2_PARAMS, 1,
			  [ptp_clock_register has 2 params is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if this_cpu_ptr exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/percpu.h>
	],[
		this_cpu_ptr(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_THIS_CPU_PTR, 1,
			  [this_cpu_ptr is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if percpu_counter_init takes 3 arguments])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/percpu_counter.h>
	],[
		percpu_counter_init(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PERCPU_COUNTER_INIT_3_ARGS, 1,
			  [percpu_counter_init takes 3 arguments])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has sk_v6_rcv_saddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		struct sock *sk;

		memset(&sk->sk_v6_rcv_saddr, 0, sizeof(sk->sk_v6_rcv_saddr));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_V6_RCV_SADDR, 1,
			  [sock.h has sk_v6_rcv_saddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has skwq_has_sleeper])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
		#include <net/sock.h>
	],[
		struct socket_wq wq;
		skwq_has_sleeper(&wq);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKWQ_HAS_SLEEPER, 1,
			  [skwq_has_sleeper is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if socket.h  has msg_iter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/socket.h>
	],[
		struct msghdr *msg;
		msg->msg_iter.nr_segs = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MSGHDR_MSG_ITER, 1,
			  [socket.h has msg_iter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uio.h has struct iov_iter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uio.h>
	],[
		struct iov_iter *iov_iter;
		iov_iter->iov = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UIO_IOV_ITER, 1,
			  [uio.h has struct iov_iter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if io.h has arch_phys_wc_add])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/io.h>
	],[
		arch_phys_wc_add(0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ARCH_PHYS_WC_ADD, 1,
			  [arch_phys_wc_add is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_physfn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev x;
		pci_physfn(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_PHYSFN, 1,
			  [pci_physfn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/printk.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/printk.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_PRINTK_H, 1,
			  [linux/printk.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if printk.h has struct va_format])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/printk.h>
	],[
		struct va_format x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VA_FORMAT, 1,
			  [va_format is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdevice.h has NETIF_F_RXHASH])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = NETIF_F_RXHASH;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXHASH, 1,
			  [NETIF_F_RXHASH is defined in netdevice.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_RXHASH])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_RXHASH;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXHASH, 1,
			  [NETIF_F_RXHASH is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_GSO_UDP_TUNNEL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_GSO_UDP_TUNNEL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_GSO_UDP_TUNNEL, 1,
			  [NETIF_F_GSO_UDP_TUNNEL is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has alloc_etherdev_mqs, alloc_etherdev_mqs, num_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
		#include <linux/netdevice.h>
	],[
		struct net_device x = {
			.num_tx_queues = 0,
			.num_tc = 0,
		};
		alloc_etherdev_mqs(0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NEW_TX_RING_SCHEME, 1,
			  [alloc_etherdev_mqs, alloc_etherdev_mqs, num_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	# same as previous check, only that num_tc comes from netdev_qos_info (RH backports)
	AC_MSG_CHECKING([if etherdevice.h has alloc_etherdev_mqs, alloc_etherdev_mqs, num_tc extended])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
		#include <linux/netdevice.h>
	],[
		struct net_device x = {
			.num_tx_queues = 0,
		};
		struct netdev_qos_info y = {
			.num_tc = 0,
		};
		alloc_etherdev_mqs(0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NEW_TX_RING_SCHEME, 1,
			  [alloc_etherdev_mqs, alloc_etherdev_mqs, num_tc extended is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([__put_task_struct],
		[kernel/fork.c],
		[AC_DEFINE(HAVE_PUT_TASK_STRUCT_EXPORTED, 1,
			[__put_task_struct is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([get_pid_task],
		[kernel/pid.c],
		[AC_DEFINE(HAVE_GET_PID_TASK_EXPORTED, 1,
			[get_pid_task is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([get_task_pid],
		[kernel/pid.c],
		[AC_DEFINE(HAVE_GET_TASK_PID_EXPORTED, 1,
			[get_task_pid is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if if_vlan.h has is_vlan_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <linux/if_vlan.h>
	],[
		struct net_device dev;
		is_vlan_dev(&dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_VLAN_DEV, 1,
			  [is_vlan_dev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_vf_mac])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_mac(struct net_device *dev, int queue, u8 *mac)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_set_vf_mac = set_vf_mac;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_VF_MAC, 1,
			  [ndo_set_vf_mac is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_vf_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_vf_stats(struct net_device *dev, int vf, struct ifla_vf_stats *vf_stats)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_get_vf_stats = get_vf_stats;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_VF_STATS, 1,
			  [ndo_get_vf_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_num_vf])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev x;
		pci_num_vf(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_NUM_VF, 1,
			  [pci_num_vf is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt.h struct rpc_rqst has member rq_xmit_bytes_sent])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_rqst x = {
			.rq_xmit_bytes_sent = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RQ_XMIT_BYTES_SENT, 1,
			  [rq_xmit_bytes_sent is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([elfcorehdr_addr],
		[kernel/crash_dump.c],
		[AC_DEFINE(HAVE_ELFCOREHDR_ADDR_EXPORTED, 1,
			[elfcorehdr_addr is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if idr.h has idr_alloc_cyclic])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		idr_alloc_cyclic(NULL, NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDR_ALLOC_CYCLIC, 1,
			  [idr_alloc_cyclic is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if idr.h has idr_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		idr_alloc(NULL, NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDR_ALLOC, 1,
			  [idr_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if random.h has prandom_u32])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/random.h>
	],[
		prandom_u32();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PRANDOM_U32, 1,
			  [prandom_u32 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if timekeeping.h has ktime_get_real_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ktime.h>
		#include <linux/timekeeping.h>
	],[
		ktime_get_real_ns();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTIME_GET_REAL_NS, 1,
			  [ktime_get_real_ns is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_HW_CSUM])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		dev->features = NETIF_F_HW_CSUM;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_HW_CSUM, 1,
			  [netdev_features.h has NETIF_F_HW_CSUM])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netns_ipv4 has sysctl_tcp_mem])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
		#include <net/protocol.h>
	],[
		struct proto proto = {
			.sysctl_mem = init_net.ipv4.sysctl_tcp_mem,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETNS_IPV4_SYSCTL_TCP_MEM, 1,
			  [struct netns_ipv4 has sysctl_tcp_mem])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_transfer_length is defind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_transfer_length(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TRANSFER_LENGTH, 1,
			  [scsi_transfer_length is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ib_signature_type is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <rdma/ib_verbs.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IB_SIGNATURE, 1,
			  [ib_signature_type is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ib signature new api is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <rdma/ib_verbs.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NEW_SIGNATURE_API, 1,
			  [ib signature new api is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has strnicmp])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/string.h>
	],[
		char a[10] = "aaa";
		char b[10] = "bbb";
		strnicmp(a, b, sizeof(a));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRNICMP, 1,
			  [strnicmp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has kfree_const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/string.h>
	],[
		const char *x;
		kfree_const(x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KFREE_CONST, 1,
			  [kfree_const is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fs.h has aio_write])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		static struct file_operations qib_file_ops = {
			.aio_write = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_AIO_WRITE, 1,
			  [aio_write is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fs.h struct file_system_type has mount])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		struct file_system_type x = {
			.mount = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FILE_SYSTEM_TYPE_MOUNT, 1,
			  [file_system_type has mount])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fs.h has get_next_ino])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		get_next_ino();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_NEXT_INO, 1,
			  [get_next_ino is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fs.h has inode_lock])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		struct inode x;
		inode_lock(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INODE_LOCK, 1,
			  [inode_lock is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if alloc_etherdev_mq is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		alloc_etherdev_mq(0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ALLOC_ETHERDEV_MQ, 1,
			  [alloc_etherdev_mq is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_set_real_num_rx_queues is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int rc = netif_set_real_num_rx_queues(NULL, 0);

		return rc;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_REAL_NUM_RX_QUEUES, 1,
			  [netif_set_real_num_rx_queues is defined])
	],[
		AC_MSG_RESULT(no)
	])
	AC_MSG_CHECKING([if ib_query_gid takes 5 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <rdma/ib_verbs.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IB_QUERY_GID_ATTRS, 1,
			  [ib_query_gid takes 5 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dcbnl_rtnl_ops has get/set ets and dcbnl defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		const struct dcbnl_rtnl_ops en_dcbnl_ops = {
			.ieee_getets = NULL,
			.ieee_setets = NULL,
		};

		struct net_device dev = {
			.dcbnl_ops = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_DCBNL_ETS, 1,
			  [ieee_getets/ieee_setets is defined and dcbnl defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if list.h hlist_for_each_entry has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/list.h>

		struct mlx5_l2_addr_node {
			struct hlist_node hlist;
			u8                addr[10];
		};
	],[
		struct mlx5_l2_addr_node *hn;
		struct hlist_head *hash;
		hlist_for_each_entry(hn, hash, hlist);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS, 1,
			  [hlist_for_each_entry has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if device.h class devnode gets umode_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		static char *cm_devnode(struct device *dev, umode_t *mode) {
			return NULL;
		}

	],[
		struct class cm_class = {
			.devnode = cm_devnode,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_DEVNODE_UMODE_T, 1,
			  [class devnode gets umode_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if device.h CLASS_ATTR_STRING])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		#include <linux/stat.h>
		#include <linux/stringify.h>
	],[
		CLASS_ATTR_STRING(abi_version, S_IRUGO,
			 __stringify(5));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_ATTR_STRING, 1,
			  [CLASS_ATTR_STRING is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if device.h class_attribute has namespace])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
	],[
		struct class_attribute x = {
			.namespace = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_ATTRIBUTE_NAMESPACE, 1,
			  [class_attribute namespace is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_namespace.h has register_net_sysctl])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/net_namespace.h>
	],[
		register_net_sysctl(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_NET_SYSCTL, 1,
			  [register_net_sysctl is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_namespace.h struct pernet_operations has id, size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/net_namespace.h>
	],[
		struct pernet_operations x = {
			.id = NULL,
			.size = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PERNET_OPERATIONS_ID_AND_SIZE, 1,
			  [struct pernet_operations has id, size is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if file.h has fdget])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/file.h>
	],[
		fdget(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FDGET, 1,
			  [fdget is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if file.h has get_unused_fd_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/file.h>
		/* Don't use backported get_unused_fd_flags
		** it uses an unexported function
		*/
		#ifdef get_unused_fd_flags
		#undef get_unused_fd_flags
		#endif
	],[
		get_unused_fd_flags(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_UNUSED_FD_FLAGS, 1,
			  [GET_UNUSED_FD_FLAGS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow.h has flowi4, flowi6 - AF specific instances])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bug.h>
		#include <net/flow.h>
	],[
		struct flowi4 fl4;
		struct flowi6 fl6;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOWI_AF_SPECIFIC_INSTANCES, 1,
			  [flowi4, flowi6  is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if icmpv6.h icmpv6_send has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/icmpv6.h>
	],[
		icmpv6_send(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ICMPV6_SEND_4_PARAMS, 1,
			  [icmpv6_send has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst_ops.h update_pmtu has 4 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/dst_ops.h>

		static void mtu_up (struct dst_entry *dst, struct sock *sk,
				    struct sk_buff *skb, u32 mtu)
		{
			return;
		}
	],[
		struct dst_ops x = {
			.update_pmtu = mtu_up,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UPDATE_PMTU_4_PARAMS, 1,
			  [update_pmtu has 4 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rtnetlink.h rtnl_link_ops newlink has 4 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/rtnetlink.h>

		static int ipoib_new_child_link(struct net *src_net, struct net_device *dev,
						struct nlattr *tb[], struct nlattr *data[])
		{
			return 0;
		}
	],[
		struct rtnl_link_ops x = {
			.newlink = ipoib_new_child_link,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RTNL_LINK_OPS_NEWLINK_4_PARAMS, 1,
			  [newlink has 4 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rtnetlink.h rtnl_link_ops dellink newlink has 2 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/rtnetlink.h>

		static void ipoib_unregister_child_dev(struct net_device *dev, struct list_head *head)
		{
			return;
		}
	],[
		struct rtnl_link_ops x = {
			.dellink = ipoib_unregister_child_dev,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RTNL_LINK_OPS_DELLINK_2_PARAMS, 1,
			  [dellink has 2 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sysfs.h struct attribute has feild owner])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysfs.h>
	],[
		struct attribute x = {
			.owner = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ATTRIBUTE_OWNER, 1,
			  [struct attribute has feild owner])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sysfs.h sysfs_get_dirent has 2 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysfs.h>
	],[
		sysfs_get_dirent(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SYSFS_GET_DIRENT_2_PARAMS, 1,
			  [sysfs_get_dirent has 2 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sysfs.h sysfs_get_dirent gets kernfs_node])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysfs.h>
	],[
		struct kernfs_node *a;
		struct kernfs_node *b;
		a = sysfs_get_dirent(b, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SYSFS_GET_DIRENT_GETS_KERNFS_NODE, 1,
			  [sysfs_get_dirent gets kernfs_node])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if module.h module_attribute gets module_kobject ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/module.h>

		static ssize_t port_gw_fs_show(struct module_attribute *attr,
					       struct module_kobject *mod, char *buf)
		{
			return 0;
		}
	],[
		struct module_attribute x = {
			.show = port_gw_fs_show,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MODULE_ATTRIBUTE_GETS_MODULE_KOBJECT, 1,
			  [sysfs_get_dirent gets kernfs_node])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ipv6.h has ipv6_addr_copy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ipv6.h>
	],[

		struct in6_addr x1;
		const struct in6_addr x2;
		ipv6_addr_copy(&x1, &x2);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_ADDR_COPY, 1,
			  [ipv6_addr_copy is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if time64.h has ns_to_timespec64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/clocksource.h>
		#include <linux/time64.h>
	],[
		ns_to_timespec64(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NS_TO_TIMESPACE64, 1,
			  [ns_to_timespec64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/flow_keys.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/flow_keys.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_FLOW_KEYS_H, 1,
			  [net/flow_keys.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_tx_queue_stopped])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_tx_queue_stopped(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_TX_QUEUE_STOPPED, 1,
			  [netif_tx_queue_stopped is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/inet_lro.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/inet_lro.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_LRO_H, 1,
			  [include/linux/inet_lro.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_xmit_stopped])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_xmit_stopped(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_XMIT_STOPPED, 1,
			  [netif_xmit_stopped is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_get_tx_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_get_tx_queue(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_GET_TX_QUEUE, 1,
			  [netdev_get_tx_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h alloc_netdev_mqs has 6 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		alloc_netdev_mqs(0, NULL, NET_NAME_UNKNOWN, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ALLOC_NETDEV_MQS_6_PARAMS, 1,
			  [alloc_netdev_mqs has 6 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h get_user_pages has 6 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		get_user_pages(0, 0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_6_PARAMS, 1,
			  [get_user_pages has 6 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm_types.h struct page has _count])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
		#include <linux/mm_types.h>
	],[
		struct page p;
		p._count.counter = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MM_PAGE__COUNT, 1,
			  [struct page has _count])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if configfs.h default_groups is list_head])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/configfs.h>
	],[
		struct config_group x = {
			.group_entry = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONFIGFS_DEFAULT_GROUPS_LIST, 1,
			  [default_groups is list_head])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/irq_poll.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq_poll.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_POLL_H, 1,
			  [include/linux/irq_poll.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if slab.h has kmalloc_array])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/slab.h>
	],[
		kmalloc_array(0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KMALLOC_ARRAY, 1,
			  [kmalloc_array is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel.h has reciprocal_scale])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kernel.h>
	],[
		reciprocal_scale(0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RECIPROCAL_SCALE, 1,
			  [reciprocal_scale is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if io_mapping_map_wc has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/io-mapping.h>
	],[
		io_mapping_map_wc(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IO_MAPPING_MAP_WC_3_PARAMS, 1,
			  [io_mapping_map_wc has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-mapping.h has struct dma_attrs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		struct dma_attrs *attrs;
		int ret;

		ret = dma_get_attr(DMA_ATTR_WRITE_BARRIER, attrs);

		return ret;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_DMA_ATTRS, 1,
			  [struct dma_attrs is defined])
	],[
		AC_MSG_RESULT(no)
	])
])
#
# COMPAT_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([COMPAT_CONFIG_HEADERS],[
#
#	Wait for remaining build tests running in background
#
	wait
#
#	Append confdefs.h files from CONFDEFS_H_DIR to the main confdefs.h file
#
	/bin/cat CONFDEFS_H_DIR/confdefs.h.* >> confdefs.h
	/bin/rm -rf CONFDEFS_H_DIR
#
#	Generate the config.h header file
#
	AC_CONFIG_HEADERS([config.h])
	EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
	AC_SUBST(EXTRA_KCFLAGS)
])

AC_DEFUN([MLNX_PROG_LINUX],
[

LB_LINUX_PATH
LB_LINUX_SYMVERFILE
LB_LINUX_CONFIG([MODULES],[],[
    AC_MSG_ERROR([module support is required to build mlnx kernel modules.])
])
LB_LINUX_CONFIG([MODVERSIONS])
LB_LINUX_CONFIG([KALLSYMS],[],[
    AC_MSG_ERROR([compat_mlnx requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

LINUX_CONFIG_COMPAT
COMPAT_CONFIG_HEADERS

])

