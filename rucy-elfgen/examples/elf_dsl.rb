include Rucy

code = "\xb7\x02\x00\x00\x00\x00\x00\x00" +
"\xbf\x20\x00\x00\x00\x00\x00\x00" +
"\x95\x00\x00\x00\x00\x00\x00\x00"

ELFFile.define do |elf|
  elf.header do |e|
    e.type ET_REL
    e.machine EM_BPF

    e.section do |scn|
      scn.name ".strtab"
      scn.type SectionType::STRTAB
    end

    e.section do |scn|
      scn.name "license"
      scn.symname "__license"
      scn.type SectionType::LICENSE
      scn.data "GPL\x00"
    end

    e.section do |scn|
      scn.name "cgroup/dev"
      scn.symname "my_prog"
      scn.type SectionType::PROG

      scn.program do |ctx|
        if ctx.minor == 9
          return 0
        else
          return 1
        end
      end

      # scn.program do
      #   return 1
      # end
    end

    # e.section do |scn|
    #   scn.name "cgroup/dev"
    #   scn.symname "my_prog"
    #   scn.type SectionType::PROG

    #   scn.data "\xb7\x00\x00\x00\x00\x00\x00\x00" +
    #            "\x95\x00\x00\x00\x00\x00\x00\x00"
    # end

    e.section do |scn|
      scn.name ".symtab"
      scn.type SectionType::SYMTAB
    end
  end
end
