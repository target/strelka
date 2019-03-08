# Exec framework is used to check whether file extraction should happen
@load base/utils/exec

# Use module to redef exports in local.bro
# redef Strelka::mime_table += {["HTTP"] = set("application/x-dosexec")};
# redef Strelka::mime_table += {["SMTP"] = set("application/x-dosexec")};
# redef Strelka::unknown_mime_source = set("HTTP", "SMTP");
module Strelka;

export {
        # Redef to extract files based on traffic `source` and `mime_type`
        const mime_table: table[string] of set[string] &redef;
        # Redef to extract files based on `filename` patterns
        const filename_re: pattern &redef;
        # Redef to extract files of undetermined `mime_type` based on traffic `source`
        const unknown_mime_source: set[string];
        # Redef to change the separator used in extracted filenames (this must match the separator used in `strelka_dirstream.py` for metadata extraction to work correctly)
        const meta_separator = "S^E^P" &redef;
        # Redef to change how often the `count_fe_directory` event runs
        const directory_count_interval = 2mins &redef;
        # Redef to change the threshold that toggles file extraction
        const directory_count_threshold = 50000 &redef;
}

# Global that controls if file extraction happens
global allow_extraction = T;

# Sequentially builds filename based on `metadata` and `separator`
function compose_filename(filename: string, metadata: vector of string, separator: string): string
    {
    for ( i in metadata )
        filename = fmt("%s%s%s", filename, metadata[i], separator);
    return filename;
    }

# Performs file extraction for each identified file
# Files have metadata embedded in their filename
function do_extraction(f: fa_file, meta: fa_metadata, c: connection)
    {
    local filename = fmt("%s%s%s%s", rand(99), rand(99), rand(99), meta_separator);
    filename = compose_filename(filename, vector(f$source, c$uid, f$id, cat(c$id$orig_h), cat(c$id$resp_h)), meta_separator);
    if ( meta?$mime_type )
        filename = compose_filename(filename, vector(meta$mime_type), meta_separator);
    else
        filename = compose_filename(filename, vector(""), meta_separator);
    filename = gsub(filename, /\//, "%2F");
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=filename]);
    }

# Performs a check on the extraction directory to determine if file extraction should be temporarily disabled
event count_fe_directory()
  {
  when ( local result = Exec::run([$cmd=fmt("ls %s | wc -l", FileExtract::prefix)]) )
      {
      if ( result?$stdout )
          {
          local file_count = to_count(result$stdout[0]);
          if ( file_count >= directory_count_threshold )
              allow_extraction = F;
          else
              allow_extraction = T;
          }
      }

  schedule directory_count_interval { count_fe_directory() };
  }

# Immediately check the length of the file extraction directory when Bro starts
event bro_init()
    {
    schedule 0secs { count_fe_directory() };
    }

# Identifies files to process for extraction
event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! f?$conns )
        return;

    if ( ! allow_extraction )
        return;

    for ( conn in f$conns )
        {
        local c = f$conns[conn];
        if ( c?$uid )
            {
            # Extract file if it meets the `mime_type` and `source` criteria in `mime_table`
            if ( f$source in mime_table && meta?$mime_type && meta$mime_type in mime_table[f$source] )
                do_extraction(f,meta,c);
            # Extract file if the filename matches `filename_re`
            else if ( f?$info && f$info?$filename && filename_re in f$info$filename )
                do_extraction(f,meta,c);
            # Extract file if it has an undetermined `mime_type` and was seen in `source`
            else if ( f$source in unknown_mime_source && ! meta?$mime_type )
                do_extraction(f,meta,c);
            }
        }
    }
