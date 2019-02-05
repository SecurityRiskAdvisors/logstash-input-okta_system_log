# encoding: utf-8

# From logstash plugin generator
require "logstash/inputs/base"
require "stud/interval"
require "socket" # for Socket.gethostname

# from okta event log plugin
require "logstash/namespace"    # not in logstash template but look slike it should be - do we need this, maybe deprecated?
require "rufus/scheduler"
require "logstash/plugin_mixins/http_client"
require "manticore"
require "base64"
require "cgi"

MAX_AUTH_TOKEN_FILE_SIZE = 1 * 2**10



class LogStash::Inputs::OktaSystemLog < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  config_name "okta_system_log"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "json"

  # Schedule of when to periodically poll from the url
  #
  # The default, `1000`, means to fetch 1000 events at a time.
  # Any value less than 1 will fetch all possible events.
  config :chunk_size, :validate => :number, :default => 1000

  # Schedule of when to periodically poll from the urls
  # Format: A hash with
  #   + key: "cron" | "every" | "in" | "at"
  #   + value: string
  # Examples:
  #   a) { "every" => "1h" }
  #   b) { "cron" => "* * * * * UTC" }
  # See: rufus/scheduler for details about different schedule options and value string format
  config :schedule, :validate => :hash, :required => true

  # THe URL for the Okta instance to access
  #
  # Format: URI
  config :url, :validate => :uri, :required => true

  # The date and time after which to fetch events
  #
  # Format: string with a RFC 3339 formatted date (e.g. 2016-10-09T22:25:06-07:00)
  config :start_date, :validate => :string

  # The free form filter to use to filter data to requirements.
  # Spec can be found at the link below
  # http://developer.okta.com/docs/api/resources/events.html#filters
  # The filter will be URL encoded by the plugin
  # The plugin will not validate the filter.
  # Use single quotes in the config file,
  # e.g. 'published gt "2017-01-01T00:00:00.000Z"'
  #
  # Format: Plain text filter field.
  config :filter, :validate => :string

  # The file in which the auth_token for Okta will be contained.
  # WARNING: This file should be VERY carefully monitored.
  # This will contain the auth_token which can have a lot access to your Okta instance.
  # It cannot be stressed enough how important it is to protect this file.
  #
  # Format: File path
  config :auth_token_file, :validate => :path

  # The auth token used to authenticate to Okta.
  # WARNING: Avoid storing the auth_token directly in this file.
  # This method is provided solely to add the auth_token via environment variable.
  # This will contain the auth_token which can have a lot access to your Okta instance.
  #
  # Format: File path
  config :auth_token_env, :validate => :string

  # Path to the state file (keeps track of the current position
  # of the API) that will be written to disk.
  # The default will write state files to `<path.data>/plugins/inputs/okta_system_log`
  # NOTE: it must be a file path and not a directory path
  #
  # Format: Filepath
  config :state_file_base, :validate => :string

  # If you'd like to work with the request/response metadata.
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  # Define the target field for placing the received data.
  # If this setting is omitted, the data will be stored at the root (top level) of the event.
  config :target, :validate => :string

  public
  Schedule_types = %w(cron every at in)
  def register

    if (@auth_token_env and @auth_token_file)
      raise LogStash::ConfigurationError, "auth_token_file and auth_token_env" +
      "cannot be set. Please select one for use."
    end

    unless (@auth_token_env or @auth_token_file)
      auth_message = "Both auth_token_file and auth_token_env cannot be empty."+
      "Please select one for use."
      raise LogStash::ConfigurationError, auth_message
    end

    if (@auth_token_file)
      begin
        if (File.size(@auth_token_file) > MAX_AUTH_TOKEN_FILE_SIZE)
          raise LogStash::ConfigurationError, "The auth_token file is too large to map"
        else
          @auth_token = File.read(@auth_token_file).chomp
          @logger.info("Successfully opened auth_token_file",:auth_token_file => @auth_token_file)
        end
      rescue LogStash::ConfigurationError
        raise
      # Some clean up magic to cover the stuff below.
      # This will keep me from stomping on signal interrupts and ctrl+c
      rescue SignalException
        raise
      rescue Exception => e
        # This is currently a bug in logstash, confirmed here:
        # https://discuss.elastic.co/t/logstash-configurationerror-but-configurationok-logstash-2-4-0/65727/2
        # Will need to determine the best way to handle this
        # Rather than testing all error conditions, this can just display them.
        # Should figure out a way to display this in a better fashion.
        raise LogStash::ConfigurationError, e.inspect
      end
    else (@auth_token_env)
      @auth_token = @auth_token_env
    end

    unless (@auth_token.index(/[^A-Za-z0-9\-_~]/).nil?)
      raise LogStash::ConfigurationError, "The auth_token should be" +
        "unreserved characters only, please check the token to ensure it is correct."
    end

    if (@start_date and @filter)
      raise LogStash::ConfigurationError, "You can only set either" +
        "start_date or filter."
    end

    if (@start_date)
      begin
        @start_date = DateTime.parse(@start_date).rfc3339(3)
      rescue ArgumentError => e
        raise LogStash::ConfigurationError, "start_date must be of the form " +
          "yyyy-MM-dd’‘T’‘HH:mm:ss.SSSZZ, e.g. 2013-01-01T12:00:00.000-07:00."
      end
      @start_date = CGI.escape(@start_date)
    end

    if (@filter)
      @filter = CGI.escape(@filter)
    end

    if (@state_file_base)
      dir_name = File.dirname(@state_file_base)
      ## Generally the state file directory will have the correct permissions
      ## so check for that case first.
      if (File.readable?(dir_name) and File.executable?(dir_name) and
        File.writable?(dir_name))

        if (Dir[@state_file_base + "*"].size > 1)
          raise LogStash::ConfigurationError, "There is more than one file" +
            "in the state file base dir (possibly an error?)." +
            "Please keep the latest/most relevant file"
        end

        @state_file = Dir[@state_file_base + "*"].last
      else
        ## Build one message for the rest of the issues
        access_message = "Could not access the state file dir" +
          "#{dir_name} for the following reasons: "

        unless (File.readable?(dir_name))
          access_message << "Cannot read #{dir_name}."
        end

        unless (File.executable?(dir_name))
          access_message << "Cannot list directory or perform special" +
          "operations on #{dir_name}."
        end

        unless (File.writable?(dir_name))
          access_message << "Cannot write to #{dir_name}."
        end

        access_message << "Please provide the appropriate permissions."

        raise LogStash::ConfigurationError, access_message

      end

      if (@state_file)
      ## Only wanna pull the base64 encoded url outta there
      unless (@state_file.eql?(@state_file_base + "start"))
        regex_state_file = %r{(?<state_file>#{@state_file_base})
          (?<state>(?:[A-Za-z0-9_-]{4})+(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?)}x
        state_url = Base64.urlsafe_decode64(@state_file.slice(regex_state_file,'state'))
        unless (state_url =~ /^#{@url}.*/)
          raise LogStash::ConfigurationError, "State file does not match #{@url}. " +
            "Please ensure the state file is correct: #{state_url}."
        end
          @url = Base64.urlsafe_decode64(@state_file.slice(regex_state_file,'state'))
      end

      else

        begin
          @state_file = @state_file_base + "start"
          # 'touch' a file to keep the conditional from happening later
                File.open(@state_file, "w") {}
          @logger.info("Created base state_file", :state_file => @state_file)
        rescue Exception => e
          raise LogStash::ConfigurationError, "Could not create #{@statefile}. " +
          "Error: #{e.inspect}."
        end
      end
    end

    params_event = Hash.new
    params_event[:limit] = @chunk_size if @chunk_size > 0
    params_event[:since] = @start_date if @start_date
    params_event[:filter] = @filter if @filter

    if (!@url.to_s.include?('?') and params_event.count > 0)
      @url = "#{@url}?" + params_event.to_a.map { |arr|"#{arr[0]}=#{arr[1]}" }.join('&')
    end

    @logger.info("Created initial URL to call", :url => @url)
    @host = Socket.gethostname

  end # def register


  def run(queue)

    msg_invalid_schedule = "Invalid config. schedule hash must contain " +
      "exactly one of the following keys - cron, at, every or in"

    raise LogStash::ConfigurationError, msg_invalid_schedule if @schedule.keys.length !=1
    schedule_type = @schedule.keys.first
    schedule_value = @schedule[schedule_type]
    raise LogStash::ConfigurationError, msg_invalid_schedule unless Schedule_types.include?(schedule_type)
    @scheduler = Rufus::Scheduler.new(:max_work_threads => 1)

    #as of v3.0.9, :first_in => :now doesn't work. Use the following workaround instead
    opts = schedule_type == "every" ? { :first_in => 0.01 } : {}
    opts[:overlap] = false;

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

    accept = "application/json"
    content_type = "application/json"

    begin
      while @continue and !stop?
        @logger.debug("Calling URL",
          :url => @url,
          :token_set => @auth_token.length > 0,
          :accept => accept,
          :content_type => content_type)

        started = Time.now

        client.async.get(@url.to_s, headers:
          {"Authorization" => "SSWS #{@auth_token}",
          "Accept" => accept,
          "Content-Type" => content_type }).
          on_success { |response | handle_success(queue, response, @url, Time.now - started) }.
          on_failure { |exception | handle_failure(queue, exception, @url, Time.now - started) }

        client.execute!
      end
    rescue Exception => e
      raise e
    ensure
      if (@state_file_base)
        new_file = @state_file_base + Base64.urlsafe_encode64(@url)
        if (@state_file != new_file )
          begin
            File.rename(@state_file,new_file)
          rescue SignalException
            raise
          rescue Exception => e
            @logger.fatal("Could not rename file",
              :old_file => @state_file,
              :new_file => new_file,
              :exception => e.inspect)
            raise
          end

          @state_file = new_file
        end
      end
    end
  end # def request_async

  private
  def handle_success(queue, response, requested_url, exec_time)

    @continue = false

    case response.code
    when 200
      Array(response.headers["link"]).each do |link_header|
        if link_header.end_with?('rel="next"')
          # @url = link_header.split(';')[0][1...-1] # ZS removed
          # ZS's fix:
          @logger.debug("Next URL Details",
            :link_header => link_header,
            :link_header_splitsplit => link_header.split(";")[1])
            # ZS: Change above debug to info if required to debug during testing
          begin
            # this works if the URL has a "self" and a "next" section
            @url = link_header.split(";")[1].split(",")[1].strip().sub("<","").sub(">","")
            @logger.info("Starting URL", :URL => @url)
          rescue
            # this works if the URL has a "next" section only
            @url = link_header.split(";")[0].strip().sub("<","").sub(">","")
          end
          # ZS: still messy but hope this works!
        end
      end

      if (response.body.length > 0)
        @codec.decode(response.body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          apply_metadata(event, requested_url, response, exec_time)
          decorate(event)
          queue << event
        end
      else
        @codec.decode("{}") do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          apply_metadata(event, requested_url, response, exec_time)
          decorate(event)
          queue << event
        end
      end

      # ZS: disable this because there is always a link header it seems
      # if (Array(response.headers["link"]).count > 1)
      #   @continue = true
      #   @logger.info("Continue status", :continue => @continue  )
      # end

      # ZS: Change below debug to info if required to debug during testing
      @logger.debug("Successful response returned", :code => response.code, :headers => response.headers)
      @logger.debug("Response body", :body => response.body)

    when 401
      @codec.decode(response.body) do |decoded|
        event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
        apply_metadata(event, requested_url, response, exec_time)
        event.set("Okta-Plugin-Status","Auth_token supplied is not valid, " +
        "validate the auth_token and update the plugin config.")
        event.set("HTTP-Code",401)
        event.tag("_okta_response_error")
        decorate(event)
        queue << event
      end

      @logger.error("Authentication required, check auth_code",
        :code => response.code,
        :headers => response.headers)
      @logger.info("Authentication failed body", :body => response.body)

    when 400
      if (response.body.include?("E0000031"))
        @codec.decode(response.body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          apply_metadata(event, requested_url, response, exec_time)
          event.set("Okta-Plugin-Status","Filter string was not valid.")
          event.set("HTTP-Code",400)
          event.tag("_okta_response_error")
          decorate(event)
          queue << event
        end

        @logger.error("Filter string was not valid",
          :response_code => response.code,
          :okta_error => "E0000031",
          :filter_string => @filter)

        @logger.info("Filter string error response",
          :response_body => response.body,
          :response_headers => response.headers)

      elsif (response.body.include?("E0000030"))

        @codec.decode(response.body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          apply_metadata(event, requested_url, response, exec_time)
          event.set("Okta-Plugin-Status","Date was not formatted correctly.")
          event.set("HTTP-Code",400)
          event.tag("_okta_response_error")
          decorate(event)
          queue << event
        end

        @logger.error("Date was not formatted correctly",
          :response_code => response.code,
          :okta_error => "E0000030",
          :date_string => @start_date)

        @logger.info("Start date error response",
          :response_body => response.body,
          :response_headers => response.headers)

      ## If the Okta error code does not match known codes
      ## Process it as a generic error
      else
        handle_unknown_http_code(queue,response,requested_url,exec_time)
      end
    else
      handle_unknown_http_code(queue,response,requested_url,exec_time)
    end

  end # def handle_success

  private
  def handle_unknown_http_code(queue,response,requested_url,exec_time)
    @codec.decode(response.body) do |decoded|
      event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
      apply_metadata(event, requested_url, response, exec_time)
      event.set("Okta-Plugin-Status","Unknown error, see Okta error")
      event.set("HTTP-Code",response.code)
      event.tag("_okta_response_error")
      decorate(event)
      queue << event
    end

    @logger.error("Okta API Error",
      :http_code => response.code,
      :body => response.body,
      :headers => response.headers)
  end # def handle_unknown_http_code

  private
  def handle_failure(queue, exception, requested_url, exec_time)

    @continue = false
    @logger.warn("Client Connection Error",
      :exception => exception.inspect)

    event = LogStash::Event.new
    apply_metadata(event, requested_url, nil, exec_time)
    event.set("http_request_failure", {
      "Okta-Plugin-Status" => "Client Connection Error",
      "Connection-Error" => exception.message,
      "backtrace" => exception.backtrace
      })
    event.tag("_http_request_failure")
    decorate(event)
    queue << event

  end # def handle_failure

  private
  def apply_metadata(event, requested_url, response=nil, exec_time=nil)
    return unless @metadata_target

    m = {}
    m = {
      "host" => @host,
      "url" => requested_url,
      "runtime_seconds" => exec_time
      }

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["retry_count"] = response.times_retried
    end

    event.set(@metadata_target,m)

    @logger.debug("Event", :event => event)

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
    rescue Exception => e
      @logger.warn("Undefined error", :exception => e.inspect)
      raise
    ensure
      if (@state_file_base)
        new_file = @state_file_base + Base64.urlsafe_encode64(@url)
        if (@state_file != new_file )
          begin
            File.rename(@state_file,new_file)
          rescue SignalException
            raise
          rescue Exception => e
            @logger.fatal("Could not rename file",
              :old_file => @state_file,
              :new_file => new_file,
              :exception => e.inspect)
            raise
          end
          @state_file = new_file
        end
      end
    end
  end # def stop


end # class LogStash::Inputs::OktaSystemLog