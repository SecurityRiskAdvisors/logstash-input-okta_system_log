require "logstash/devutils/rspec/spec_helper"
require 'logstash/inputs/okta_system_log'
require 'flores/random'
require "timecop"
require "base64"
require "rspec/wait"

describe LogStash::Inputs::OktaSystemLog do
  let(:queue) { Queue.new }
  let(:default_schedule) {
    { "every" => "30s" }
  }
  let(:default_limit) { 1000 }
  let(:default_auth_token_key) { "asdflkjasdflkjasdf932r098-asdf" }
  let(:default_host) { "localhost" }
  let(:metadata_target) { "_http_poller_metadata" }
  let(:default_state_file_path) { "/dev/null" }
  let(:default_header) { {"x-rate-limit-remaining" => 3, "x-rate-limit-limit" => 4} }
  let(:default_rate_limit) { "RATE_MEDIUM" }

  let(:default_opts) {
    {
      "schedule" => default_schedule,
      "limit" => default_limit,
      "hostname" => default_host,
      "auth_token_key" => default_auth_token_key,
      "metadata_target" => metadata_target,
      "state_file_path" => default_state_file_path,
      "rate_limit"  => default_rate_limit,
      "codec" => "json"
    }
  }
  let(:klass) { LogStash::Inputs::OktaSystemLog }

  describe "config" do
    shared_examples "configuration errors" do
      it "raises an exception" do
        expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
      end
    end

    subject { klass.new(opts) }

    before(:each) do
      subject
      allow(File).to receive(:directory?).with(opts["state_file_path"]) { false }
      allow(File).to receive(:exist?).with(opts["state_file_path"]) { true }
      allow(File).to receive(:stat).with(opts["state_file_path"]) { double("file_stat") }
      # We don't really want to use the atomic write function
      allow(subject).to receive(:detect_write_method).with(opts["state_file_path"]) { subject.method(:non_atomic_write) }
      allow(File).to receive(:size).with(opts["state_file_path"]) { 0 }
      allow(subject).to receive(:update_state_file) { nil }

      # Might need these later
      #allow(File).to receive(:read).with(opts["state_file_path"], 1) { "\n" }
      #allow(LogStash::Environment).to receive(:windows?) { false }
      #allow(File).to receive(:chardev?).with(opts["state_file_path"]) { false }
      #allow(File).to receive(:blockdev?).with(opts["state_file_path"]) { false }
      #allow(File).to receive(:socket?).with(opts["state_file_path"]) { false }
    end

    context "the hostname is not in the correct format" do
      let(:opts) { default_opts.merge({"hostname" => "asdf__"}) }
      include_examples("configuration errors")
    end

    context "both hostname and custom_url are set" do
      let(:opts) { default_opts.merge({"custom_url" => "http://localhost/foo/bar"}) }
      include_examples("configuration errors")
    end

    context "custom_url is in an incorrect format" do
      let(:opts) { 
        opts = default_opts.merge({"custom_url" => "htp://___/foo/bar"}).clone
        opts.delete("hostname")
        opts
      }
      include_examples("configuration errors")
    end

    context "The since parameter is not in the correct format" do
      let(:opts) { default_opts.merge({"since" => "1234567890"}) }
      include_examples("configuration errors")
    end

    context "The limit parameter is too large" do
      let(:opts) { default_opts.merge({"limit" => 10000}) }
      include_examples("configuration errors")
    end

    context "The limit is too small" do
      let(:opts) { default_opts.merge({"limit" => -10000}) }
      include_examples("configuration errors")
    end

    context "the q parameter has too many items" do
      let(:opts) { default_opts.merge({"q" => Array.new(size=11, obj="a")}) }
      include_examples("configuration errors")
    end

    context "the q parameter item has a space" do
      let(:opts) { default_opts.merge({"q" => ["a b"]}) }
      include_examples("configuration errors")
    end

    context "the q parameter item is too long" do
      let(:opts) { default_opts.merge({"q" => ["a" * 41]}) }
      include_examples("configuration errors")
    end

    context "the rate_limit parameter is too large" do
      let(:opts) { default_opts.merge({"rate_limit" => "1.5"}) }
      include_examples("configuration errors")
    end

    context "the rate_limit parameter is too small" do
      let(:opts) { default_opts.merge({"rate_limit" => "-0.5"}) }
      include_examples("configuration errors")
    end

    context "the rate_limit parameter uses a non-standard stand-in" do
      let(:opts) { default_opts.merge({"rate_limit" => "RATE_CRAWL"}) }
      include_examples("configuration errors")
    end

    context "the metadata target is not set" do
      let(:opts) { 
        opts = default_opts.clone
        opts.delete("metadata_target")
        opts
      }
      it "sets the metadata function to apply_metadata" do
        subject.register
        expect(subject.instance_variable_get("@metadata_function")).to eql(subject.method(:apply_metadata))
        expect(subject.instance_variable_get("@metadata_target")).to eql("@metadata")
      end
    end


    context "auth_token management" do
      let(:auth_file_opts) {
        auth_file_opts = default_opts.merge({"auth_token_file" => "/dev/null"}).clone
        auth_file_opts.delete("auth_token_key")
        auth_file_opts
      }

      context "custom_auth_header is defined with auth_token_key" do
        let(:opts) {default_opts.merge({"custom_auth_header" => "Basic user:password"})}
        include_examples("configuration errors")
      end

      context "custom_auth_header is defined with auth_token_file" do
        let(:opts) {auth_file_opts.merge({"custom_auth_header" => "Basic user:password"})}
        include_examples("configuration errors")
      end

      context "both auth_token key and file are provided" do
        let(:opts) {default_opts.merge({"auth_token_file" => "/dev/null"})}
        include_examples("configuration errors")
      end

      context "neither auth_token key nor file are provided" do
        let(:opts) {
          opts = default_opts.clone
          opts.delete("auth_token_key")
          opts
        }
        include_examples("configuration errors")
      end

      context "auth_token_file is too large" do
        let(:opts) {auth_file_opts}
        before {allow(File).to receive(:size).with(opts["auth_token_file"]) { 1 * 2**11 }}
        include_examples("configuration errors")
      end
      
      context "auth_token_file could not be read" do
        let(:opts) {auth_file_opts}
        before {
          allow(File).to receive(:size).with(opts["auth_token_file"]) { 10 }
          allow(File).to receive(:read).with(opts["auth_token_file"], 10) { raise IOError }
        }
        include_examples("configuration errors")
      end

      context "auth_token returns an unauthorized error" do
        let(:opts) { default_opts }
        before do
          subject.client.stub("https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                              :body => "{}",
                              :code => klass::HTTP_UNAUTHORIZED_401
          )
        end
        include_examples("configuration errors")
      end
    end
  end

  describe "instances" do
    subject { klass.new(default_opts) }

    before do
        subject.client.stub("https://#{default_opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                            :body => "{}",
                            :code => klass::HTTP_OK_200,
                            :headers => default_header
        )
       allow(File).to receive(:directory?).with(default_state_file_path) { false }
       allow(File).to receive(:exist?).with(default_state_file_path) { true }
       allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
       # We don't really want to use the atomic write function
       allow(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
       allow(File).to receive(:size).with(default_state_file_path) { 0 }
       allow(subject).to receive(:update_state_file) { nil }
       subject.register
    end

    describe "#run" do
      it "should setup a scheduler" do
        runner = Thread.new do
          subject.run(double("queue"))
          expect(subject.instance_variable_get("@scheduler")).to be_a_kind_of(Rufus::Scheduler)
        end
        runner.kill
        runner.join
      end
    end

    describe "#run_once" do
      it "should issue an async request for each url" do
        expect(subject).to receive(:request_async).with(queue).once

        subject.send(:run_once, queue) # :run_once is a private method
      end
    end
  end

  describe "scheduler configuration" do
    before do
      instance.client.stub("https://#{default_opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                          :body => "{}",
                          :code => klass::HTTP_OK_200,
                          :headers => default_header
      )
       allow(File).to receive(:directory?).and_call_original
       allow(File).to receive(:directory?).with(default_state_file_path) { false }
       allow(File).to receive(:exist?).with(default_state_file_path) { true }
       allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
       # We don't really want to use the atomic write function
       allow(instance).to receive(:detect_write_method).with(default_state_file_path) { instance.method(:non_atomic_write) }
       allow(File).to receive(:size).with(default_state_file_path) { 0 }
       allow(instance).to receive(:update_state_file) { nil }
      instance.register
    end

    context "given 'cron' expression" do
      let(:opts) { default_opts.merge("schedule" => {"cron" => "* * * * * UTC"}) }
      let(:instance) { klass.new(opts) }
      it "should run at the schedule" do
        Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
        Timecop.scale(60)
        queue = Queue.new
        runner = Thread.new do
          instance.run(queue)
        end
        sleep 3
        instance.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(2)
        Timecop.return
      end
    end

    context "given 'at' expression" do
      let(:opts) { default_opts.merge("schedule" => {"at" => "2000-01-01 00:05:00 +0000"}) }
      let(:instance) { klass.new(opts) }
      it "should run at the schedule" do
        Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
        Timecop.scale(60 * 5)
        queue = Queue.new
        runner = Thread.new do
          instance.run(queue)
        end
        sleep 2
        instance.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(1)
        Timecop.return
      end
    end

    context "given 'every' expression" do
      let(:opts) { default_opts.merge("schedule" => {"every" => "2s"}) }
      let(:instance) { klass.new(opts) }
      it "should run at the schedule" do
        queue = Queue.new
        runner = Thread.new do
          instance.run(queue)
        end
        #T       0123456
        #events  x x x x
        #expects 3 events at T=5
        sleep 5
        instance.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(3)
      end
    end

    context "given 'in' expression" do
      let(:opts) { default_opts.merge("schedule" => {"in" => "2s"}) }
      let(:instance) { klass.new(opts) }
      it "should run at the schedule" do
        queue = Queue.new
        runner = Thread.new do
          instance.run(queue)
        end
        sleep 3
        instance.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(1)
      end
    end
  end

  describe "events" do
    shared_examples("matching metadata") {
      let(:metadata) { event.get(metadata_target) }
      let(:options) { defined?(settings) ? settings : opts }
      # The URL gets modified b/c of the limit that is placed on the API
      #let(:metadata_url) { "https://#{options["hostname"]+klass::OKTA_EVENT_LOG_PATH}?limit=#{options["limit"]}" }
      let(:metadata_url) { 
        if (custom_settings)
          options["custom_url"]+"?limit=#{options["limit"]}"
        else
          "https://#{options["hostname"]+klass::OKTA_EVENT_LOG_PATH}?limit=#{options["limit"]}" 
        end
      }

      it "should have the correct request url" do
          expect(metadata["url"].to_s).to eql(metadata_url)
        end

      it "should have the correct code" do
        expect(metadata["code"]).to eql(code)
      end
    }

    shared_examples "unprocessable_requests" do
      let(:poller) { klass.new(settings) }
      subject(:event) {
        poller.send(:run_once, queue)
        queue.pop(true)
      }

      before do
        unless (custom_settings)
          poller.client.stub("https://#{settings["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                              :body => "{}",
                              :code => klass::HTTP_OK_200,
                              :headers => default_header
                              )
        end
        allow(File).to receive(:directory?).with(default_state_file_path) { false }
        allow(File).to receive(:exist?).with(default_state_file_path) { true }
        allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        allow(poller).to receive(:detect_write_method).with(default_state_file_path) { poller.method(:non_atomic_write) }
        allow(File).to receive(:size).with(default_state_file_path) { 0 }
        allow(poller).to receive(:update_state_file) { nil }
        poller.register
        allow(poller).to receive(:handle_failure).and_call_original
        allow(poller).to receive(:handle_success)
        event # materialize the subject
      end

      it "should enqueue a message" do
        expect(event).to be_a(LogStash::Event)
      end

      it "should enqueue a message with 'http_request_error' set" do
        expect(event.get("http_request_error")).to be_a(Hash)
      end

      it "should tag the event with '_http_request_error'" do
        expect(event.get("tags")).to include('_http_request_error')
      end

      it "should invoke handle failure exactly once" do
        expect(poller).to have_received(:handle_failure).once
      end

      it "should not invoke handle success at all" do
        expect(poller).not_to have_received(:handle_success)
      end

      include_examples("matching metadata")

    end

    context "with a non responsive server" do
      context "due to an invalid hostname" do # Fail with handlers
        let(:custom_settings) { false }
        let(:hostname) { "thouetnhoeu89ueoueohtueohtneuohn" }
        let(:code) { nil } # no response expected

        let(:settings) { default_opts.merge("hostname" => hostname) }

        include_examples("unprocessable_requests")
      end

      context "due to a non-existent host" do # Fail with handlers
        let(:custom_settings) { true }
        let(:custom_url) { "http://thouetnhoeu89ueoueohtueohtneuohn/path/api" }
        let(:code) { nil } # no response expected

        let(:settings) { 
        
          settings = default_opts.merge("custom_url" => custom_url).clone
          settings.delete("hostname")
          settings
        }

        include_examples("unprocessable_requests")


      end
      context "due to a bogus port number" do # fail with return?
        let(:invalid_port) { Flores::Random.integer(65536..1000000) }
        let(:custom_settings) { true }
        let(:custom_url) { "http://127.0.0.1:#{invalid_port}" }
        let(:settings) { 
          settings = default_opts.merge("custom_url" => custom_url.to_s).clone
          settings.delete("hostname")
          settings
        }
        let(:code) { nil } # No response expected

        include_examples("unprocessable_requests")
      end
    end

    describe "a valid request and decoded response" do
      let(:payload) {{"a" => 2, "hello" => ["a", "b", "c"]}}
      let(:response_body) { LogStash::Json.dump(payload) }
      let(:code) { klass::HTTP_OK_200 }
      let(:hostname) { default_host }
      let(:custom_settings) { false }
      let(:headers) { default_header }

      let(:opts) { default_opts }
      let(:instance) {
        klass.new(opts)
      }

      subject(:event) {
        queue.pop(true)
      }

      before do
        instance.client.stub("https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                            :body => "{}",
                            :code => klass::HTTP_OK_200,
                            :headers => headers
                            )
        allow(File).to receive(:directory?).with(default_state_file_path) { false }
        allow(File).to receive(:exist?).with(default_state_file_path) { true }
        allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        allow(instance).to receive(:detect_write_method).with(default_state_file_path) { instance.method(:non_atomic_write) }
        allow(File).to receive(:size).with(default_state_file_path) { 0 }
        allow(instance).to receive(:update_state_file) { nil }

        instance.register
        allow(instance).to receive(:decorate)
        instance.client.stub(%r{#{opts["hostname"]}.*}, 
                             :body => response_body,
                             :code => code,
                             :headers => headers
        )

        allow(instance).to receive(:get_epoch) { 1 }
        allow(instance).to receive(:local_sleep).with(1) { 1 }
        instance.send(:run_once, queue)
      end

      it "should have a matching message" do
        expect(event.to_hash).to include(payload)
      end

      it "should decorate the event" do
        expect(instance).to have_received(:decorate).once
      end

      include_examples("matching metadata")
      
      context "with an empty body" do
        let(:response_body) { "" }
        it "should return an empty event" do
          expect(event.get("[_http_poller_metadata][response_headers][content-length]")).to eql("0")
        end
      end

      context "with metadata omitted" do
        let(:opts) {
          opts = default_opts.clone
          opts.delete("metadata_target")
          opts
        }

        it "should not have any metadata on the event" do
          expect(event.get(metadata_target)).to be_nil
        end
      end

      context "with a specified target" do
        let(:target) { "mytarget" }
        let(:opts) { default_opts.merge("target" => target) }

        it "should store the event info in the target" do
          # When events go through the pipeline they are java-ified
          # this normalizes the payload to java types
          payload_normalized = LogStash::Json.load(LogStash::Json.dump(payload))
          expect(event.get(target)).to include(payload_normalized)
        end
      end

      context "with non-200 HTTP response codes" do
        let(:code) { |example| example.metadata[:http_code] }
        let(:response_body) { "{}" }

        it "responds to a 500 code", :http_code => 500 do
          expect(event.to_hash).to include("http_response_error")
          expect(event.to_hash["http_response_error"]).to include({"http_code" => code})
          expect(event.get("tags")).to include('_http_response_error')
        end
        it "responds to a 401/Unauthorized code", :http_code => 401 do
          expect(event.to_hash).to include("okta_response_error")
          expect(event.to_hash["okta_response_error"]).to include({"http_code" => code})
          expect(event.get("tags")).to include('_okta_response_error')
        end
        it "responds to a 400 code", :http_code => 400 do
          expect(event.to_hash).to include("okta_response_error")
          expect(event.to_hash["okta_response_error"]).to include({"http_code" => code})
          expect(event.get("tags")).to include('_okta_response_error')
        end
        context "when the request rate limit is reached" do
          let(:headers) { {"x-rate-limit-remaining" => 0, "x-rate-limit-reset" => 0} }
          it "reports and sleeps for the designated time", :http_code => 429  do
            expect(instance).to have_received(:get_epoch)
            expect(instance).to have_received(:local_sleep).with(1)
            expect(event.to_hash).to include("okta_response_error")
            expect(event.to_hash["okta_response_error"]).to include({"http_code" => code})
            expect(event.to_hash["okta_response_error"]).to include({"reset_time" => 0})
            expect(event.get("tags")).to include('_okta_response_error')
          end
        end
        context "specific okta errors" do
          let(:payload) { {:okta_error => "E0000031" } }
          let(:response_body) { LogStash::Json.dump(payload) }

          describe "filter string error" do
            let(:payload) { {:okta_error => "E0000031" } }
            let(:response_body) { LogStash::Json.dump(payload) }
            it "generates a filter string error event", :http_code => 400 do
              expect(event.to_hash).to include("okta_response_error")
              expect(event.to_hash["okta_response_error"]).to include({"http_code" => code})
              expect(event.to_hash["okta_response_error"]).to include({"okta_plugin_status" => "Filter string was not valid."})
              expect(event.get("tags")).to include('_okta_response_error')
            end
          end

          describe "start_date error" do
            let(:payload) { {:okta_error => "E0000030" } }
            let(:response_body) { LogStash::Json.dump(payload) }
            it "generates a start_date error event", :http_code => 400 do
              expect(event.to_hash).to include("okta_response_error")
              expect(event.to_hash["okta_response_error"]).to include({"http_code" => code})
              expect(event.to_hash["okta_response_error"]).to include({"okta_plugin_status" => "since was not valid."})
              expect(event.get("tags")).to include('_okta_response_error')
            end
          end
        end
      end
    end
  end

  describe "stopping" do
    let(:config) { default_opts }
    before do
      allow(File).to receive(:directory?).with(default_state_file_path) { false }
      allow(File).to receive(:exist?).with(default_state_file_path) { true }
      allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
      # We don't really want to use the atomic write function
      allow(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
      allow(File).to receive(:size).with(default_state_file_path) { 0 }
      allow(subject).to receive(:update_state_file) { nil }
    end
    it_behaves_like "an interruptible input plugin"
  end

  describe "state file" do
    context "when being setup" do

      let(:opts) { 
        opts = default_opts.merge({"state_file_path" => default_state_file_path}).clone
        opts
      }

      subject { klass.new(opts) }

      let(:state_file_url) { "https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH}?limit=#{opts["limit"]}&after=asdfasdf" }
      let(:test_url) { "https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH}?limit=#{opts["limit"]}" }
      let(:state_file_url_changed) { "http://example.com/?limit=1000" }

      before(:each) do
        subject.client.stub("https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                            :body => "{}",
                            :code => klass::HTTP_OK_200,
                            :headers => default_header
                            )
      end


      it "sets up the state file correctly" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { 0 }
        subject.register
      end

      it "raises an error on file read" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { 10 }
        expect(File).to receive(:read).with(default_state_file_path, 10) { raise IOError }
        expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
      end

      it "creates a url based on the state file" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { "#{state_file_url}\n".length }
        expect(File).to receive(:read).with(default_state_file_path, "#{state_file_url}\n".length) { "#{state_file_url}\n" }
        subject.register
        expect(subject.instance_variable_get("@url")).to eql(state_file_url)
      end

      it "uses the URL from options when state file is empty" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { 0 }
        subject.register
        expect(subject.instance_variable_get("@url").to_s).to eql(test_url)
      end

      it "raises an error when the config url is not part of the saved state" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { "#{state_file_url_changed}\n".length }
        expect(File).to receive(:read).with(default_state_file_path, "#{state_file_url_changed}\n".length) { "#{state_file_url_changed}\n" }
        expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
      end

      it "sets the the failure mode to error" do
        expect(File).to receive(:directory?).with(default_state_file_path) { false }
        expect(File).to receive(:exist?).with(default_state_file_path) { true }
        expect(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        expect(subject).to receive(:detect_write_method).with(default_state_file_path) { subject.method(:non_atomic_write) }
        expect(File).to receive(:size).with(default_state_file_path) { 0 }
        subject.register
        expect(subject.instance_variable_get("@state_file_failure_function")).to eql(subject.method(:error_state_file))
      end
    end
    
    context "when running" do
      let(:opts) { 
        opts = default_opts.merge({"state_file_path" => default_state_file_path}).clone
        opts
      }
      let(:instance) { klass.new(opts) }

      let(:payload) { '[{"eventId":"tevIMARaEyiSzm3sm1gvfn8cA1479235809000"}]}]' }
      let(:response_body) { LogStash::Json.dump(payload) }
      
      let(:url_initial) { "https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH}?after=1" }
      let(:url_final) { "https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH}?after=2" }
      let(:headers) { default_header.merge({"link" => ["<#{url_initial}>; rel=\"self\"", "<#{url_final}>; rel=\"next\""]}).clone }
      let(:code) { klass::HTTP_OK_200 }
      let(:file_path) { opts['state_file_dir'] + opts["state_file_prefix"] }
      let(:file_obj) { double("file") }
      let(:fd) { double("fd") }
      let(:time_anchor) { 2 }

      before(:each) do |example|
        allow(File).to receive(:directory?).with(default_state_file_path) { false }
        allow(File).to receive(:exist?).with(default_state_file_path) { true }
        allow(File).to receive(:stat).with(default_state_file_path) { double("file_stat") }
        # We don't really want to use the atomic write function
        allow(instance).to receive(:detect_write_method).with(default_state_file_path) { instance.method(:non_atomic_write) }
        allow(File).to receive(:size).with(default_state_file_path) { "#{url_initial}\n".length }
        allow(File).to receive(:read).with(default_state_file_path, "#{url_initial}\n".length) { "#{url_initial}\n" }

        instance.client.stub("https://#{opts["hostname"]+klass::OKTA_EVENT_LOG_PATH+klass::AUTH_TEST_URL}", 
                            :body => "{}",
                            :code => code,
                            :headers => default_header
                            )
        instance.register
        instance.client.stub( url_initial,
          :headers => headers,
          :body => response_body,
          :code => code )

        allow(instance).to receive(:handle_failure) { instance.instance_variable_set(:@continue,false) }
        allow(instance).to receive(:get_time_int) { time_anchor }
      end

      it "updates the state file after data is fetched" do
        expect(IO).to receive(:sysopen).with(default_state_file_path, "w+") { fd }
        expect(IO).to receive(:open).with(fd).and_yield(file_obj)
        expect(file_obj).to receive(:write).with("#{url_final}\n") { url_final.length + 1 }
        instance.client.stub( url_final,
          :headers => default_header.merge({:link => "<#{url_final}>; rel=\"self\""}).clone,
          :body => "{}",
          :code => code )
        instance.send(:run_once, queue)
      end

      it "updates the state file after a failure" do
        expect(IO).to receive(:sysopen).with(default_state_file_path, "w+") { fd }
        expect(IO).to receive(:open).with(fd).and_yield(file_obj)
        expect(file_obj).to receive(:write).with("#{url_final}\n") { url_final.length + 1 }
        instance.send(:run_once, queue)
      end
      
      context "when stop is called" do
        it "saves the state in the file" do
          # We are still testing the same condition
          expect(IO).to receive(:sysopen).with(default_state_file_path, "w+") { fd }
          expect(IO).to receive(:open).with(fd).and_yield(file_obj)
          expect(file_obj).to receive(:write).with("#{url_final}\n") { url_final.length + 1 }

          # Force a sleep to make the thread hang in the failure condition.
          allow(instance).to receive(:handle_failure) {
            instance.instance_variable_set(:@continue,false)
            sleep(30)
          }

          plugin_thread = Thread.new(instance,queue) { |subject, queue| 
            instance.send(:run, queue) 
          }

          # Sleep for a bit to make sure things are started.
          sleep 0.5
          expect(plugin_thread).to be_alive

          instance.do_stop

          # As they say in the logstash thread, why 3?
          # Because 2 is too short, and 4 is too long.
          wait(3).for { plugin_thread }.to_not be_alive
        end
      end
    end
  end
end
