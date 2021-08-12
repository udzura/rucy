module Rucy
  class ELFFile
    def self.current_model
      @model
    end

    def self.set_model(model)
      @model ||= model
    end

    def self.define(&b)
      @model = self.new
      b.call(@model)
    end

    def header(&b)
      @ehdr = EHdrValue.new
      b.call(@ehdr)
    end
  end

  class EHdrValue
    def type(v)
      @type = v
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
  end

  class ScnValue
    def type(v)
      @type = v
    end

    def name(v)
      @name = v
    end

    def data(v)
      @data = v
    end

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
