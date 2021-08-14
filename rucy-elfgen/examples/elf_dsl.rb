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
      # scn.data "aaaaaaaa" + "aaaaaaaa"
      # scn.data "\xb7\x00\x00\x00\x00\x00\x00\x00" +
      #          "\x95\x00\x00\x00\x00\x00\x00\x00"

      scn.data code
    end

    e.section do |scn|
      scn.name ".symtab"
      scn.type SectionType::SYMTAB
    end
  end
end
