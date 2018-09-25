# Redef to extract files based on traffic `source` and `mime_type`
const mime_table: table[string] of set[string] = {
    ["FTP_DATA"] =  set("application/x-dosexec"),
    ["HTTP"] =      set("application/x-dosexec"),
    ["SMB"] =       set("application/x-dosexec"),
    ["SMTP"] =      set("application/x-dosexec")
} &redef;
# Redef to extract files based on `filename` patterns
const filename_re: pattern = /(\.dll|\.exe)$/ &redef;
# Redef to extract files of undetermined `mime_type` based on traffic `source`
const unknown_mime_source: set[string] = set("FTP_DATA", "HTTP", "SMB", "SMTP") &redef;
# Redef to change the separator used in extracted filenames. This must match the separator used in `stream_directory.py` for metadata extraction to work correctly.
const meta_separator: string = "S^E^P" &redef;

# Sequentially builds filename based on `metadata` and `separator`
function compose_filename(filename: string, metadata: vector of string, separator: string): string
    {
    for ( i in metadata )
        filename = fmt("%s%s%s", filename, metadata[i], separator);
    return filename;
    }

# Performs file extraction for each identified file
function do_extraction(f: fa_file, meta: fa_metadata, c: connection)
    {
    # Filenames begin with random numbers to ensure there are no filename clashes
    local filename = fmt("%s%s%s%s", rand(99), rand(99), rand(99), meta_separator);

    # If `meta.mime_type` exists, then it is added to the `filename`
    # Otherwise, insert an empty string
    if ( meta?$mime_type )
        filename = compose_filename(filename, vector(f$source, c$uid, f$id, cat(c$id$orig_h), cat(c$id$resp_h), meta$mime_type), meta_separator);
    else
        filename = compose_filename(filename, vector(f$source, c$uid, f$id, cat(c$id$orig_h), cat(c$id$resp_h), ""), meta_separator);

    # If the traffic source is SMTP, then use `c.smtp.subject` as metadata
    # Otherwise, insert an empty string
    if ( f$source == "SMTP" && c?$smtp )
        {
        if  ( c$smtp?$subject )
            filename = compose_filename(filename, vector(c$smtp$subject), meta_separator);
        else
            filename = compose_filename(filename, vector(""), meta_separator);
        }
    # If the traffic source is HTTP, then use `c.http.host` as metadata
    # Otherwise, insert an empty string
    else if ( f$source == "HTTP" && c?$http )
        {
        if ( c$http?$host )
            filename = compose_filename(filename, vector(c$http$host), meta_separator);
        else
            filename = compose_filename(filename, vector(""), meta_separator);
        }
    # If the traffic source is not handled, then insert an empty string
    else
        filename = compose_filename(filename, vector(""), meta_separator);

    # "/" is an invalid filename character and will always be present in `meta.mime_type`
    # Linux can only handle filenames up to 255 characters
    filename = gsub(filename, /\//, "%2F")[:255];
    # Begin file extraction
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=filename]);
    }

# Identifies files to process for extraction
event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! f?$conns )
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
