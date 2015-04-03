stream = io.connect(STREAM_URL);

// arch is public data
arch = undefined;
function on_arch(msg) { DS("arch");
  //p(msg);
  arch = msg;
} stream.on("arch", on_arch);

function on_instructions(msg) { DS("instructions");
  var clnum = Session.get("clnum");
  var idump = "";
  for (var i = 0; i<msg.length;i++) {
    var ins = msg[i];

    if (ins.clnum === clnum) {
      Session.set('iaddr', ins.address);
      Session.set('iview', ins.address);
    }

    if (ins.name == undefined) {
      ins.name = "";
    }

    // compute the dynamic stuff
    idump +=
       '<div class="instruction" style="margin-left: '+(ins.depth*10)+'px">'+
        '<div class="change '+(ins.slice ? "halfhighlight": "")+' clnum clnum_'+ins.clnum+'">'+ins.clnum+'</div> '+
        '<span class="insaddr datainstruction addr addr_'+ins.address+'">'+ins.address+'</span> '+
        '<div class="instructiondesc">'+highlight_instruction(ins.instruction)+'</div> '+
        '<span class="comment comment_'+ins.address+'">'+(ins.comment !== undefined ? "; "+ins.comment : "")+'</span>'+
      '</div>';
  }
  $('#idump').html(idump);
  rehighlight();
  replace_names();
} stream.on('instructions', on_instructions);

Deps.autorun(function() { DA("emit getinstructions");
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  stream.emit('getinstructions', forknum, clnum, clnum-8, clnum+10);
});

