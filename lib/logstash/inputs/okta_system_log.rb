# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "rufus/scheduler"
require "socket" # for Socket.gethostname
require "logstash/plugin_mixins/http_client"
require "manticore"
require "uri"


class LogStash::Inputs::OktaSystemLog < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  MAX_MMAP_FILE_SIZE = 1 * 2**10
  OKTA_EVENT_LOG_PATH = "/api/v1/logs"
  AUTH_TEST_URL = "?limit=1#auth-test"
   
  HTTP_OK_200 = 200
  HTTP_BAD_REQUEST_400 = 400
  HTTP_UNAUTHORIZED_401 = 401
   
  # Sleep Timers
  SLEEP_API_RATE_LIMIT = 1
  SLEEP_STATE_FILE_RETRY = 0.25
   
 config_name "okta_system_log"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "json"
  
  # Schedule of when to periodically poll from the url
  # Format: A hash with
  #   + key: "cron" | "every" | "in" | "at"
  #   + value: string
  # Examples:
  #   a) { "every" => "1h" }
  #   b) { "cron" => "* * * * * UTC" }
  # See: rufus/scheduler for details about different schedule options and value string format
  # See here for rate limits: https://developer.okta.com/docs/api/resources/system_log#rate-limits
  config :schedule, :validate => :hash, :required => true

  # The Okta host which you would like to use
  # The system log path will be appended onto this host
  # Ex: dev-instance.oktapreview.com
  # Ex: org-name.okta.com
  #
  # Format: Hostname
  config :hostname, :validate => :string

  # The date and time after which to fetch events
  # NOTE: By default the API will only fetch events seven days before time of the first call
  #  To get more data, please select the desired date to start fetching data
  # Docs: https://developer.okta.com/docs/api/resources/system_log#request-parameters
  # Okta log retention by default is 90 days, it is suggested to set the date accordingly
  #
  # Format: string with a RFC 3339 formatted date (e.g. 2016-10-09T22:25:06-07:00)
  config :since, :validate => :string

  # Set how many messages you want to pull with each request
  # The default, `1000`, means to fetch 1000 events at a time.
  #
  # Format: Number between 1 and 1000
  # Default: 1000
  config :limit, :validate => :number, :default => 1000

  # The free form filter to use to filter data to requirements.
  # Docs: https://developer.okta.com/docs/api/resources/system_log#expression-filter
  # The filter will be URL encoded by the plugin
  # The plugin will not validate the filter.
  # Use single quotes in the config file,
  # e.g. 'published gt "2017-01-01T00:00:00.000Z"'
  #
  # Format: Plain text filter field.
  config :filter, :validate => :string

  # Filters the log events results by one or more exact keywords in a list
  # Docs: https://developer.okta.com/docs/api/resources/system_log#keyword-filter
  # Documentation bug: https://github.com/okta/okta.github.io/issues/2500
  # The plugin will URL encode the list
  # The query cannot have more than ten items
  # Query items cannot have a space
  # Query items cannot be longer than 40 chars
  # 
  # Format: A list with the items to query on
  # Ex. ["foo", "bar"]
  # Ex. ["new", "york"]
  config :q, :validate => :string, :list => true

  # The file in which the auth_token for Okta will be contained.
  # This will contain the auth_token which can have a lot access to your Okta instance.
  # It cannot be stressed enough how important it is to protect this file.
  # NOTE: This option is deprecated and will be removed in favor of the secrets store.
  # 
  # Format: File path
  config :auth_token_file, :validate => :path, :deprecated => true
  
  # The auth token used to authenticate to Okta.
  # NOTE: Avoid storing the auth_token directly in the config file.
  # This method is provided solely to add the auth_token via secrets store.
  # Docs: https://www.elastic.co/guide/en/logstash/current/keystore.html
  # WARNING: This will contain the auth_token which can have a lot access to your Okta instance.
  #
  # Format: File path
  config :auth_token_key, :validate => :password

  # Path to the state file (keeps track of the current position
  # of the API) that will be written to disk.
  # The default will write state files to `<path.data>/plugins/inputs/okta_system_log`
  # NOTE: it must be a file path and not a directory path
  #
  # Format: Filepath
  config :state_file_path, :validate => :string

  # Option to cause a fatal error if the state file can't update
  # Normal operation will generate an error when state file update fails
  #   However, it will continue pull events from API
  # This option will reverse that paradigm and exit if a failure occurs
  #
  # Format: Boolean
  config :state_file_fatal_falure, :validate => :boolean, :default => false

  # If you'd like to work with the request/response metadata.
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  # Define the target field for placing the received data.
  # If this setting is omitted
  #   the data will be stored at the root (top level) of the event.
  #
  # Format: String
  config :target, :validate => :string
  
  # The URL for the Okta instance to access
  # NOTE: This is useful for an iPaaS instance
  #
  # Format: URI
  config :custom_url, :validate => :uri, :required => false

  # Custom authorization header to be added instead of default header
  # This is useful for an iPaaS only
  # Example: Basic dXNlcjpwYXNzd29yZA==
  # This will be added to the authorization header accordingly
  # Authorization: Basic dXNlcjpwYXNzd29yZA==
  # NOTE: It is suggested to use the secrets store to store the header
  # It is an error to set both this and the auth_token
  # 
  # Format: string
  config :custom_auth_header, :validate => :password, :required => false

  # This option is obsoleted in favor of hostname or custom_url.
  # THe URL for the Okta instance to access
  #
  # Format: URI
  config :url, :validate => :uri, 
    :obsolete => "url is obsolete, please use hostname or custom_url instead"

  # This option is obsolete
  # The throttle value to use for noisy log lines (at the info level)
  # Currently just one log statement (successful HTTP connects)
  # The value is used to mod a counter, so set it appropriately for log levels
  # NOTE: This value will be ignored when the log level is debug or trace
  #
  # Format: Integer
  config :log_throttle, :validate => :number, 
    :obsolete => "Log throttling is longer required"

  # This option is obsoleted in favor of limit.
  # Set how many messages you want to pull with each request
  #
  # The default, `1000`, means to fetch 1000 events at a time.
  # Any value less than 1 will fetch all possible events.
  config :chunk_size, :validate => :number, 
    :obsolete => "chunk_size is obsolete, please use limit instead"
  
  # This option is obsoleted in favor of since.
  # The date and time after which to fetch events
  #
  # Format: string with a RFC 3339 formatted date 
  # Ex. 2016-10-09T22:25:06-07:00
  config :start_date, :validate => :string,
    :obsolete => "start_date is obsolete, please use since instead"

  # This option is obsoleted in favor of auth_token_key.
  # The auth token used to authenticate to Okta.
  # WARNING: Avoid storing the auth_token directly in this file.
  # This method is provided solely to add the auth_token via environment variable.
  # This will contain the auth_token which can have a lot access to your Okta instance.
  #
  # Format: File path
  config :auth_token_env, :validate => :string,
    :obsolete => "auth_token_env is obsolete, please use auth_token_key instead"

  # This option is obsoleted in favor of state_file_path.
  # The base filename to store the pointer to the current location in the logs
  # This file will be renamed with each new reference to limit loss of this data
  # The location will need at least write and execute privs for the logstash user
  #
  # Format: Filepath
  # This is not the filepath of the file itself, but to generate the file.
  config :state_file_base, :validate => :string,
    :obsolete => "state_file_base is obsolete, use state_file_path instead"
 
  public
  Schedule_types = %w(cron every at in)
  def register

    @trace_log_method = detect_trace_log_method()

    if (@limit < 1 or @limit > 1000 or !@limit.integer?)
      @logger.fatal("Invalid `limit` value: #{@limit}. " +
        "Config limit should be an integer between 1 and 1000.")
      raise LogStash::ConfigurationError, "Invalid `limit` value: #{@limit}. " + 
        "Config limit should be an integer between 1 and 1000."
    end

    unless (@hostname.nil? ^ @custom_url.nil?)
      @logger.fatal("Please configure the hostname " +
        "or the custom_url to use.")
      raise LogStash::ConfigurationError, "Please configure the hostname " +
        "or the custom_url to use."
    end

    if (@hostname)
      begin
        url_obj = URI::HTTPS.build(
                    :host => @hostname,
                    :path => OKTA_EVENT_LOG_PATH)
      rescue URI::InvalidComponentError
        @logger.fatal("Invalid hostname, " + 
          "could not configure URL. hostname = #{@hostname}.")
        raise LogStash::ConfigurationError, "Invalid hostname, " + 
          "could not configure URL. hostname = #{@hostname}."
      end
    end
    if (@custom_url)
      begin
        # The URL comes in as a SafeURI object which doesn't get parsed nicely.
        # Cast to string helps with that
        # Really only happens during tests and not during normal operations
        url_obj = URI.parse(@custom_url.to_s)
      rescue URI::InvalidURIError
        @logger.fatal("Invalid custom_url, " +
          "please verify the URL. custom_url = #{@custom_url}")
        raise LogStash::ConfigurationError, "Invalid custom_url, " + 
          "please verify the URL. custom_url = #{@custom_url}"
      end

    end
    
    if (@since)
      begin
        @since = DateTime.parse(@since).rfc3339(0)
      rescue ArgumentError => e
        @logger.fatal("since must be of the form " +
          "yyyy-MM-dd’‘T’‘HH:mm:ssZZ, e.g. 2013-01-01T12:00:00-07:00.")
        raise LogStash::ConfigurationError, "since must be of the form " +
          "yyyy-MM-dd’‘T’‘HH:mm:ssZZ, e.g. 2013-01-01T12:00:00-07:00."
      end
    end

    if (@q)
      if (@q.length > 10)
        msg = "q cannot have more than 10 terms. " + 
          "Use the `filter` to limit the query."
        @logger.fatal(msg)
        raise LogStash::ConfigurationError, msg
      end
      space_errors = []
      length_errors = []
      for item in @q
        if (item.include? " ")
          space_errors.push(item)
        elsif (item.length > 40)
          length_errors.push(item)
        end
      end
      if (space_errors.length > 0)
        @logger.fatal("q items cannot contain a space. " +
          "Items: #{space_errors.join(" ")}.")
        raise LogStash::ConfigurationError, "q items cannot contain a space. " +
          "Items: #{space_errors.join(" ")}."
      end
      if (length_errors.length > 0)
        msg = "q items cannot contain be longer than 40 characters. " + 
          "Items: #{length_errors.join(" ")}."
        @logger.fatal(msg)
        raise LogStash::ConfigurationError, msg
      end
    end

    if (@custom_auth_header)
      if (@auth_token_key or @auth_token_file)
        @logger.fatal("If custom_auth_header is used " +
          "you cannot set auth_token_key or auth_token_file")
        raise LogStash::ConfigurationError, "If custom_auth_header is used " + 
          "you cannot set auth_token_key or auth_token_file"
      end
    else
      unless (@auth_token_key.nil? ^ @auth_token_file.nil?)
        auth_message = "Set only the  auth_token_key or auth_token_file."
        @logger.fatal(auth_message)
        raise LogStash::ConfigurationError, auth_message
      end

      if (@auth_token_file)
        begin
          auth_file_size = File.size(@auth_token_file)
          if (auth_file_size > MAX_MMAP_FILE_SIZE)
            @logger.fatal("The auth_token file " +
              "is too large to map")
            raise LogStash::ConfigurationError, "The auth_token file " + 
              "is too large to map"
          else
            @auth_token = LogStash::Util::Password.new(
                            File.read(@auth_token_file, auth_file_size).chomp)
            @logger.info("Successfully opened auth_token_file",
              :auth_token_file => @auth_token_file)
          end
        rescue LogStash::ConfigurationError
          raise
        rescue => e
          # This is a bug in older versions of  logstash, confirmed here: 
          # https://discuss.elastic.co/t/logstash-configurationerror-but-configurationok-logstash-2-4-0/65727/2
          @logger.fatal(e.inspect)
          raise LogStash::ConfigurationError, e.inspect
        end
      else 
        @auth_token = @auth_token_key
      end

      if (@auth_token)
        begin
          response = client.get(
            url_obj.to_s+AUTH_TEST_URL,
              headers: {'Authorization' => "SSWS #{@auth_token.value}"},
              request_timeout: 2,
              connect_timeout: 2,
              socket_timeout: 2)
          if (response.code == HTTP_UNAUTHORIZED_401)
            @logger.fatal("The auth_code provided " +
              "was not valid, please check the input")
            raise LogStash::ConfigurationError, "The auth_code provided " + 
              "was not valid, please check the input"
          end
        rescue LogStash::ConfigurationError
          raise
        rescue Manticore::ManticoreException => m
          msg = "There was a connection error verifying the auth_token, " + 
            "continuing without verification"
          @logger.error(msg, :client_error => m.inspect)
        rescue => e
          @logger.fatal("Could not verify auth_token, " +
            "error: #{e.inspect}")
          raise LogStash::ConfigurationError, "Could not verify auth_token, " + 
            "error: #{e.inspect}"
        end
      end
    end

    params_event = Hash.new
    params_event[:limit] = @limit if @limit > 0
    params_event[:since] = @since if @since
    params_event[:filter] = @filter if @filter
    params_event[:q] = @q.join(" ") if @q
    url_obj.query = URI.encode_www_form(params_event)


    # This check is Logstash 5 specific.  If the class does not exist, and it
    # won't in older versions of Logstash, then we need to set it to nil.
    settings = defined?(LogStash::SETTINGS) ? LogStash::SETTINGS : nil

    if (@state_file_path.nil?)
      begin
        base_state_file_path = build_state_file_base(settings)
      rescue LogStash::ConfigurationError
        raise
      rescue => e
        @logger.fatal("Could not set up state file", :exception => e.inspect)
        raise LogStash::ConfigurationError, e.inspect
      end
      file_prefix = "#{@hostname}_system_log_state"
      case Dir[File.join(base_state_file_path,"#{file_prefix}*")].size
      when 0
        # Build a file name randomly
        @state_file_path = File.join(
                                      base_state_file_path, 
                                      rand_filename("#{file_prefix}"))
        @logger.info('No state_file_path set, generating one based on the ' +
          '"hostname" setting', 
          :state_file_path => @state_file_path.to_s, 
          :hostname => @hostname)
      when 1
        @state_file_path = Dir[File.join(base_state_file_path,"#{file_prefix}*")].last
        @logger.info('Found state file based on the "hostname" setting', 
          :state_file_path => @state_file_path.to_s, 
          :hostname => @hostname)
      else
        msg = "There is more than one file" +
          "in the state file base dir (possibly an error?)." +
          "Please keep the latest/most relevant file.\n" +
          "Directory: #{base_state_file_path}"
        @logger.fatal(msg)
        raise LogStash::ConfigurationError, msg
      end
        
    else
      @state_file_path = File.path(@state_file_path)
      if (File.directory?(@state_file_path))
        @logger.fatal("The `state_file_path` argument must point to a file, " +
          "received a directory: #{@state_file_path}")
        raise LogStash::ConfigurationError, "The `state_file_path` argument " +
          "must point to a file, received a directory: #{@state_file_path}"
      end
    end
    begin
      @state_file_stat = detect_state_file_mode(@state_file_path)
    rescue => e
      @logger.fatal("Error getting state file info. " + 
        "Exception: #{e.inspect}")
      raise LogStash::ConfigurationError, "Error getting state file info. " +
        "Exception: #{e.inspect}"
    end

    @write_method = detect_write_method(@state_file_path)

    begin
      state_file_size = File.size(@state_file_path)
      if (state_file_size > 0)
        if (state_file_size > MAX_MMAP_FILE_SIZE)
          @logger.fatal("The state file: " +
            "#{@state_file_path} is too large to map")
          raise LogStash::ConfigurationError, "The state file: " +
            "#{@state_file_path} is too large to map"
        end
        state_url = File.read(@state_file_path, state_file_size).chomp
        if (state_url.length > 0)
          state_url_obj = URI.parse(state_url)
          @logger.info(
            "Successfully opened state_file_path",
            :state_url => state_url_obj.to_s,
            :state_file_path => @state_file_path)
          if (@custom_url)
           unless (url_obj.hostname == state_url_obj.hostname)
            @logger.fatal("The state URL " +
              "does not match configured URL. ",
              :configured_url => url_obj.to_s, 
              :state_url => state_url_obj.to_s)
            raise LogStash::ConfigurationError, "The state URL " +
              "does not match configured URL. " +
              "Configured url: #{url_obj.to_s}, state_url: #{state_url_obj.to_s}"
            end
          else
            unless (state_url_obj.hostname == @hostname and
              state_url_obj.path == OKTA_EVENT_LOG_PATH)
              @logger.fatal("The state URL " +
                "does not match configured URL. " +
                :configured_url => url_obj.to_s, 
                :state_url => state_url_obj.to_s)
              raise LogStash::ConfigurationError, "The state URL " +
                "does not match configured URL. " +
                "Configured url: #{url_obj.to_s}, state_url: #{state_url_obj.to_s}"
            end
          end
          url_obj = state_url_obj
        end
      end
    rescue LogStash::ConfigurationError
      raise
    rescue URI::InvalidURIError => e
      @logger.fatal("Could not parse url " +
        "from state_file_path. URL: #{state_url}. Error: #{e.inspect}.")
      raise LogStash::ConfigurationError, "Could not parse url " +
        "from state_file_path. URL: #{state_url}. Error: #{e.inspect}."
    rescue => e
      @logger.fatal(e.inspect)
      raise LogStash::ConfigurationError, e.inspect
    end

    @url = url_obj.to_s

    @logger.info("Created initial URL to call", :url => @url)
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    if (@metadata_target)
      @metadata_function = method(:apply_metadata)
    else
      @metadata_function = method(:noop)
    end

    if (@state_file_fatal_falure)
      @state_file_failure_function = method(:fatal_state_file)
    else
      @state_file_failure_function = method(:error_state_file)
    end

  end # def register


  def run(queue)
    
    msg_invalid_schedule = "Invalid config. schedule hash must contain " +
      "exactly one of the following keys - cron, at, every or in"

    @logger.fatal(msg_invalid_schedule) if @schedule.keys.length !=1
    raise LogStash::ConfigurationError, msg_invalid_schedule if @schedule.keys.length !=1
    schedule_type = @schedule.keys.first
    schedule_value = @schedule[schedule_type]
    @logger.fatal(msg_invalid_schedule) unless Schedule_types.include?(schedule_type)
    raise LogStash::ConfigurationError, msg_invalid_schedule unless Schedule_types.include?(schedule_type)
    @scheduler = Rufus::Scheduler.new(:max_work_threads => 1)
    
    #as of v3.0.9, :first_in => :now doesn't work. Use the following workaround instead
    opts = schedule_type == "every" ? { :first_in => 0.01 } : {} 
    opts[:overlap] = false;

    @logger.info("Starting event stream with the configured URL.", 
      :url => @url)
    @scheduler.send(schedule_type, schedule_value, opts) { run_once(queue) }

    @scheduler.join

  end # def run

  private 
  def run_once(queue)

    request_async(queue)

  end # def run_once

  private
  def request_async(queue)

    @continue = true

    header_hash = {
                  "Accept" => "application/json",
                  "Content-Type" => "application/json"
                  }

    if (@auth_token)
      header_hash["Authorization"] = "SSWS #{@auth_token.value}"
    elsif (@custom_auth_header)
      header_hash["Authorization"] = @custom_auth_header.value
    end

    begin
      while @continue and !stop?
        @logger.debug("Calling URL", 
          :url => @url, 
          :token_set => !@auth_token.nil?)

        started = Time.now

        client.async.get(@url.to_s, headers: header_hash).
          on_success { |response| handle_success(queue, response, @url, Time.now - started) }.
          on_failure { |exception| handle_failure(queue, exception, @url, Time.now - started) }

        client.execute!
      end
    rescue => e
      @logger.fatal(e.inspect)
      raise e
    ensure
      update_state_file()
    end
  end # def request_async

  private
  def update_state_file()
    for i in 1..3
      @trace_log_method.call("Starting state file update",
        :state_file_path => @state_file_path,
        :url => @url,
        :attempt_num  => i)

      begin
        @write_method.call(@state_file_path, @url)
      rescue => e
        @logger.warn("Could not save state, retrying",
          :state_file_path => @state_file_path,
          :url => @url,
          :exception => e.inspect)

        sleep SLEEP_STATE_FILE_RETRY
        next
      end
      @logger.debug("Successfully wrote the state file",
        :state_file_path => @state_file_path,
        :url => @url,
        :attempts => i)
      # Break out of the loop once you're done
      return nil
    end
    @state_file_failure_function.call()
  end # def update_state_file

  private
  def handle_success(queue, response, requested_url, exec_time)

    @continue = false

    case response.code
    when HTTP_OK_200
      ## Some benchmarking code for reasonings behind the methods.
      ## They aren't great benchmarks, but basic ones that proved a point.
      ## If anyone has better/contradicting results let me know
      #
      ## Some system info on which these tests were run:
      #$ cat /proc/cpuinfo | grep -i "model name" | uniq -c
      #       4 model name      : Intel(R) Core(TM) i7-3740QM CPU @ 2.70GHz
      #
      #$ free -m
      #              total        used        free      shared  buff/cache   available
      #              Mem:           1984         925         372           8         686         833
      #              Swap:          2047           0        2047
      #
      #str = '<https://dev-instance.oktapreview.com/api/v1/events?after=tevHLxinRbATJeKgKjgXGXy0Q1479278142000&limit=1000>; rel="next"'
      #require "benchmark"
      #
      #
      #n = 50000000
      #
      #
      #Benchmark.bm do |x|
      #  x.report { n.times { str.include?('rel="next"') } } # (2) 23.008853sec @50000000 times
      #  x.report { n.times { str.end_with?('rel="next"') } } # (1) 16.894623sec @50000000 times
      #  x.report { n.times { str =~ /rel="next"$/ } } # (3) 30.757554sec @50000000 times
      #end
      #
      #Benchmark.bm do |x|
      #  x.report { n.times { str.match(/<([^>]+)>/).captures[0] } } # (2) 262.166085sec @50000000 times
      #  x.report { n.times { str.split(';')[0][1...-1] } } # (1) 31.673270sec @50000000 times
      #end
      
      # Store the next URL to call from the header
      next_url = nil
      Array(response.headers["link"]).each do |link_header|
        if link_header.end_with?('rel="next"')
          next_url = link_header.split(';')[0][1...-1]
        end
      end

      # Store the number of records processed this run
      records = 0

      if (response.body.length > 0)
        @codec.decode(response.body) do |decoded|
          @logger.debug("Pushing event to queue")
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          @metadata_function.call(event, requested_url, response, exec_time)
          decorate(event)
          queue << event
          records = records + 1
        end
      else
        @codec.decode("{}") do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          @metadata_function.call(event, requested_url, response, exec_time)
          decorate(event)
          queue << event
        end
      end

      if (!next_url.nil? and next_url != @url)
        @url = next_url
        # if we received the record limit, then continue with another request. Else, record the next_url for the next scheduled run.
        #   This avoids a rate limit error in high volume instances where new logs are always available, but not at the defined limit
        @continue = (records >= @limit) ? true : false
        @logger.debug("Continue status", :continue => @continue  )
        # Add a sleep since we're gonna hit the API again
        sleep SLEEP_API_RATE_LIMIT
      end

      @trace_log_method.call("Response body", :body => response.body)

    when HTTP_UNAUTHORIZED_401
      @codec.decode(response.body) do |decoded|
        event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
        @metadata_function.call(event, requested_url, response, exec_time)
        event.set("okta_response_error", {
          "okta_plugin_status" => "Auth_token supplied is not valid, " +
            "validate the auth_token and update the plugin config.",
          "http_code" => 401
        })
        event.tag("_okta_response_error")
        decorate(event)
        queue << event
      end

      @logger.error("Authentication required, check auth_code", 
        :code => response.code, 
        :headers => response.headers)
      @trace_log_method.call("Authentication failed body", :body => response.body)

    when HTTP_BAD_REQUEST_400
      if (response.body.include?("E0000031"))
        @codec.decode(response.body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          @metadata_function.call(event, requested_url, response, exec_time)
          event.set("okta_response_error", {
            "okta_plugin_status" => "Filter string was not valid.",
            "http_code" => 400
          })
          event.tag("_okta_response_error")
          decorate(event)
          queue << event
        end

        @logger.error("Filter string was not valid", 
          :response_code => response.code,
          :okta_error => "E0000031",
          :filter_string => @filter)

        @logger.debug("Filter string error response",
          :response_body => response.body,
          :response_headers => response.headers)

      elsif (response.body.include?("E0000030"))

        @codec.decode(response.body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          @metadata_function.call(event, requested_url, response, exec_time)
          event.set("okta_response_error", {
            "okta_plugin_status" => "since was not valid.",
            "http_code" => 400
          })
          event.tag("_okta_response_error")
          decorate(event)
          queue << event
        end

        @logger.error("Date was not formatted correctly",
          :response_code => response.code,
          :okta_error => "E0000030",
          :date_string => @since)

        @logger.debug("Start date error response",
          :response_body => response.body,
          :response_headers => response.headers)

      ## If the Okta error code does not match known codes
      ## Process it as a generic error
      else
        handle_unknown_okta_code(queue,response,requested_url,exec_time)
      end
    else
      handle_unknown_http_code(queue,response,requested_url,exec_time)
    end

  end # def handle_success

  private
  def handle_unknown_okta_code(queue,response,requested_url,exec_time)
    @codec.decode(response.body) do |decoded|
      event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
      @metadata_function.call(event, requested_url, response, exec_time)
      event.set("okta_response_error", {
        "okta_plugin_status" => "Unknown error code from Okta",
        "http_code" => response.code,
      })
      event.tag("_okta_response_error")
      decorate(event)
      queue << event
    end

    @logger.error("Okta API Error", 
      :http_code => response.code, 
      :body => response.body,
      :headers => response.headers)

  end # def handle_unknown_okta_code

  private
  def handle_unknown_http_code(queue,response,requested_url,exec_time)
    @codec.decode(response.body) do |decoded|
      event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
      @metadata_function.call(event, requested_url, response, exec_time)

      event.set("http_response_error", {
        "okta_plugin_status" => "Unknown HTTP code, review HTTP errors",
        "http_code" => response.code,
        "http_headers" => response.headers
      })
      event.tag("_http_response_error")
      decorate(event)
      queue << event
    end

    @logger.error("HTTP Error", 
      :http_code => response.code, 
      :body => response.body,
      :headers => response.headers)
  end # def handle_unknown_http_code

  private
  def handle_failure(queue, exception, requested_url, exec_time)

    @continue = false
    @logger.error("Client Connection Error", 
      :exception => exception.inspect)

    event = LogStash::Event.new
    @metadata_function.call(event, requested_url, nil, exec_time)
    event.set("http_request_error", {
      "okta_plugin_status" => "Client Connection Error",
      "connect_error" => exception.message,
      "backtrace" => exception.backtrace
      })
    event.tag("_http_request_error")
    decorate(event)
    queue << event

  end # def handle_failure

  private
  def apply_metadata(event, requested_url, response=nil, exec_time=nil)

    m = {
      "host" => @host,
      "url" => requested_url
      }

    if exec_time
      m["runtime_seconds"] = exec_time.round(3)
    end

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["retry_count"] = response.times_retried
    end

    event.set(@metadata_target,m)

  end

  # Dummy function to handle noops
  private
  def noop(*args)
    return
  end

  private
  def fatal_state_file()
    @logger.fatal("Unable to save state file after retrying. Exiting...",
      :url => @url,
      :state_file_path => @state_file_path)

    @logger.fatal("Unable to save state_file_path, " +
      "#{@state_file_path} after retrying.")
    raise LogStash::EnvironmentError, "Unable to save state_file_path, " + 
      "#{@state_file_path} after retrying."
  end

  private
  def error_state_file()
    @logger.error("Unable to save state_file_path after retrying three times",
      :url => @url,
      :state_file_path => @state_file_path)
  end

  # based on code from logstash-input-file
  private
  def atomic_write(path, content)
    write_atomically(path) do |io|
      io.write("#{content}\n")
    end
  end

  private
  def non_atomic_write(path, content)
    IO.open(IO.sysopen(path, "w+")) do |io|
      io.write("#{content}\n")
    end
  end


  # Write to a file atomically. Useful for situations where you don't
  # want other processes or threads to see half-written files.
  #
  #   File.write_atomically('important.file') do |file|
  #     file.write('hello')
  #   end
  private
  def write_atomically(file_name)

    # Create temporary file with identical permissions
    begin
      temp_file = File.new(rand_filename(file_name), "w", @state_file_stat.mode)
      temp_file.binmode
      return_val = yield temp_file
    ensure
      temp_file.close
    end

    # Overwrite original file with temp file
    File.rename(temp_file.path, file_name)

    # Unable to get permissions of the original file => return
    return return_val if @state_file_mode.nil?

    # Set correct uid/gid on new file
    File.chown(@state_file_stat.uid, @state_file_stat.gid, file_name) if old_stat

    return return_val
  end

  private
  def rand_filename(prefix) #:nodoc:
    [ prefix, Thread.current.object_id, Process.pid, rand(1000000) ].join('.')
  end

  ## Not used -- but keeping it in case I need to use it at some point
  ## Private utility method.
  #private
  #def probe_stat_in(dir) #:nodoc:
  #  begin
  #    basename = rand_filename(".permissions_check")
  #    file_name = File.join(dir, basename)
  #    #FileUtils.touch(file_name)
  #    # 'touch' a file to keep the conditional from happening later
  #    File.open(file_name, "w") {}
  #    File.stat(file_name)
  #  rescue
  #    # ...
  #  ensure
  #    File.delete(file_name) if File.exist?(file_name)
  #  end
  #end

  private
  def build_state_file_base(settings) #:nodoc:
    if (settings.nil?)
      @logger.warn("Attempting to use LOGSTASH_HOME. Note that this method is deprecated. " \
                   "Consider upgrading or using state_file_path config option instead.")
      # This section is going to be deprecated eventually, as path.data will be
      # the default, not an environment variable (SINCEDB_DIR or LOGSTASH_HOME)
      # NOTE: I don't have an answer for this right now, but this raise needs to be moved to `register`
      if ENV["LOGSTASH_HOME"].nil?
        @logger.error("No settings or  LOGSTASH_HOME environment variable set, I don't know where " +
                      "to keep track of the files I'm watching. " + 
                      "Set state_file_path in " +
                      "in your Logstash config for the file input with " +
                      "state_file_path '#{@state_file_path.inspect}'")
        raise LogStash::ConfigurationError, 'The "state_file_path" setting ' +
          'was not given and the environment variable "LOGSTASH_HOME" ' + 
          'is not set so we cannot build a file path for the state_file_path.'
      end
      logstash_data_path = File.path(ENV["LOGSTASH_HOME"])
    else
      logstash_data_path = settings.get_value("path.data")
    end
    File.join(logstash_data_path, "plugins", "inputs", "okta_system_log").tap do |path|
      # Ensure that the filepath exists before writing, since it's deeply nested.
      nested_dir_create(path)
    end
  end

  private
  def nested_dir_create(path) # :nodoc:
    dirs = []
    until File.directory?(path)
      dirs.push path
      path = File.dirname(path)
    end

    dirs.reverse_each do |dir|
      Dir.mkdir(dir)
    end
  end

  private
  def log_trace(message, vars = {})
    @logger.trace(message, vars)
  end

  private
  def log_debug(message, vars = {})
    @logger.debug(message, vars)
  end

  private
  def detect_trace_log_method() #:nodoc:
    begin
      if (@logger.trace?)
        return method(:log_trace)
      end
    rescue NoMethodError
      @logger.info("Using debug instead of trace due to lack of support" + 
        "in this version.")
      return method(:log_debug)
    end
    return method(:log_trace)
  end

  private
  def is_defined(str) #:nodoc:
    return !(str.nil? or str.length == 0)
  end

  def detect_write_method(path)
    if (LogStash::Environment.windows? || 
      File.chardev?(path) || 
      File.blockdev?(path) || 
      File.socket?(path))
      @logger.info("State file cannot be updated using an atomic write, " +
        "using non-atomic write", :state_file_path => path)
      return method(:non_atomic_write)
    else
      return method(:atomic_write)
    end
  end

  def detect_state_file_mode(path)
    if (File.exist?(path))
      old_stat = File.stat(path)
    else
      # We need to create a file anyway so check it with the file created
      # # If not possible, probe which are the default permissions in the
      # # destination directory.
      # old_stat = probe_stat_in(File.dirname(@state_file_path))
      
      # 'touch' a file 
      File.open(path, "w") {}
      old_stat = File.stat(path)
    end

    return old_stat ? old_stat : nil

  end

  public
  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
    begin 
      @scheduler.stop
    rescue NoMethodError => e
      unless (e.message == "undefined method `stop' for nil:NilClass")
        raise
      end
    rescue => e
      @logger.warn("Undefined error", :exception => e.inspect)
      raise
    ensure
      if (is_defined(@url))
        update_state_file()
      end
    end
  end # def stop
end # class LogStash::Inputs::OktaSystemLog
