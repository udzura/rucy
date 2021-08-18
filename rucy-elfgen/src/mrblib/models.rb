module Rucy
  class ELFFile
    def self.current_model
      @model
    end

    def self.set_model(model)
      @model ||= model
    end

    def self.program
      prog = current_model.header.sections.find {|scn| scn.type == SectionType::PROG }
      if prog
        prog.data
      else
        nil
      end
    end

    def self.reset_program(data)
      prog = current_model.header.sections.find {|scn| scn.type == SectionType::PROG }
      if prog
        prog.data(data)
      else
        raise "Invalid call context: Maybe a bug"
      end
    end

    def self.define(&b)
      @model = self.new
      b.call(@model)
    end

    def header(&b)
      if b
        @ehdr = EHdrValue.new
        b.call(@ehdr)
      else
        @ehdr
      end
    end
  end

  class EHdrValue
    def type(v=nil)
      if v
        @type = v
      else
        @type
      end
    end

    def machine(v)
      @machine = v
    end

    def section(&b)
      @scns ||= []
      scn = ScnValue.new
      b.call(scn)

      @scns << scn
    end

    def sections
      @scns
    end
  end

  class ScnValue
    def type(v=nil)
      if v
        @type = v
      else
        @type
      end
    end

    def name(v)
      @name = v
    end

    def data(v=nil, &prog)
      if prog
        @data = prog
      elsif v
        @data = v
      else
        @data
      end
    end
    alias program data

    def symname(v)
      @symname = v
    end
  end

  module SectionType
    NULL = 0
    STRTAB = 1
    PROG = 2
    LICENSE = 3
    SYMTAB = 4
  end

  ET_NONE = 0
  ET_REL = 1
  ET_EXEC = 2
  ET_DYN = 3
  ET_CORE = 4
  ET_NUM = 5

  EM_NONE = 0;
  EM_SPARC = 2;
  EM_IAMCU = 6;
  EM_MIPS = 8;
  EM_BPF = 247
end
