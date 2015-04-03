# QIRA

[![Build Status](https://travis-ci.org/BinaryAnalysisPlatform/qira.svg?branch=master)](https://travis-ci.org/BinaryAnalysisPlatform/qira)

* QIRA is a competitor to strace and gdb
* See http://qira.me/ for high level usage information
* All QIRA code is released under GPLv2 or BSD
* Other code in this repo released under it's respective license

## Installing release

See instructions on [qira.me](http://qira.me/) to install 1.0, the most stable version of QIRA

## Installing trunk

<pre>
cd ~/
git clone https://github.com/BinaryAnalysisPlatform/qira.git
cd qira/
./install.sh
</pre>

## Installation Extras

* ./fetchlibs.sh will fetch the libraries for armhf, armel, aarch64, and ppc
* ./pin_build.sh will install the QIRA PIN plugin, allowing --pin to work


## Releases

* v1.1 -- Support for names and comments. Static stuff added. Register colors.
* v1.0 -- Perf is good! Tons of bugfixes. Quality software. http://qira.me/
* v0.9 -- Function indentation. haddrline added(look familiar?). Register highlighting in hexdump.
* v0.8 -- Intel syntax! Shipping CDA(cda a.out) and experimental PIN backend. Bugfixes. Windows support?
* v0.7 -- DWARF support. Builds QEMU if distributed binaries don't work. Windows IDA plugin.
* v0.6 -- Added changes before webforking. Highlight strace addresses. Default on analysis.
* v0.5 -- Fixed regression in C++ database causing wrong values. Added PowerPC support. Added "A" button.
* v0.4 -- Using 50x faster C++ database. strace support. argv and envp are there.
* v0.3 -- Built in socat, multiple traces, forks(experimental). Somewhat working x86-64 and ARM support
* v0.2 -- Removed dependency on mongodb, much faster. IDA plugin fixes, Mac version.
* v0.1 -- Initial release


## UI

<pre>
At the top, you have 4 boxes, called the controls.
  Blue = change number, Grey = fork number
  Red = instruction address(iaddr), Yellow = data address(daddr)

On the left you have the vtimeline, this is the full trace of the program.
  The top is the start of the program, the bottom is the end/current state.
  More green = deeper into a function.
  The currently selected change is blue, red is every passthrough of the current iaddr
  Bright yellow is a write to the daddr, dark yellow is a read from the daddr.
  This color scheme is followed everywhere

Below the controls, you have the idump, showing instructions near the current change
Under that is the regviewer, datachanges, hexeditor, and strace, all self explanatory.
</pre>


## Mouse Actions
Click on vtimeline to navigate around. Right click forks to delete them. Click on data(or doubleclick if highlightable) to follow in data. Right click on instruction address to follow in instruction.

## Keyboard Shortcuts in web/client/controls.js
<pre>
j -- next invocation of instruction
k -- prev invocation of instruction

shift-j -- next toucher of data
shift-k -- prev toucher of data

m -- go to return from current function
, -- go to start of current function

z -- zoom out max on vtimeline

l -- set iaddr to instruction at current clnum

left  -- -1 fork
right -- +1 fork
up    -- -1 clnum
down  -- +1 clnum

esc -- back

shift-c -- clear all forks

n -- rename instruction
shift-n -- rename data
; -- add comment at instruction
shift-; -- add comment at data

g -- go to change, address, or name
space -- toggle flat/function view

p -- analyze function at iaddr
c -- make code at iaddr, one instruction
a -- make ascii at iaddr
d -- make data at iaddr
u -- make undefined at iaddr
</pre>

## Installation on Windows (experimental)

* Install git and python 2.7.9
* Run install.bat


## Session state
<pre>
clnum -- Selected changelist number
forknum -- Selected fork number
iaddr -- Selected instruction address
daddr -- Selected data address

cview -- Viewed changelists in the vtimeline
dview -- Viewed window into data in the hexeditor
iview -- Viewed address in the static view

max_clnum -- Max changelist number for each fork
dirtyiaddr -- Whether we should update the clnum based on the iaddr or not
flat -- if we are in flat view
</pre>

