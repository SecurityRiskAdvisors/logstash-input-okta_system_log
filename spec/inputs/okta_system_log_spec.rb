# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/okta_system_log"
require "flores/random"
require "timecop"
require "base64"
require "rspec/wait"

describe LogStash::Inputs::OktaSystemLog do
  let(:queue) { Queue.new }
  let(:default_schedule) {
    { "every" => "30s" }
  }
  let(:default_chunk_size) { 1000 }
  let(:default_auth_token_env) { "asdflkjasdflkjasdf932r098-asdf" }
  let(:default_url) { "https://changeme.changeme.com:65535/" }
  let(:metadata_target) { "_http_poller_metadata" }
  let(:default_opts) {
    {
      "schedule" => default_schedule,
      "chunk_size" => default_chunk_size,
      "url" => default_url,
      "auth_token_env" => default_auth_token_env,
      "metadata_target" => metadata_target,
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
    end

    context "The start date is not in the correct format" do
      let(:opts) { default_opts.merge({"start_date" => "1234567890"}) }
      include_examples("configuration errors")
    end

    context "Both start date and filter are provided" do
      let(:opts) { default_opts.merge({"start_date" => "2013-01-01T12:00:00.000-07:00","filter" => "this is a filter"}) }
      include_examples("configuration errors")
    end

    context "auth_token management" do
      let(:auth_file_opts) {
        auth_file_opts = default_opts.merge({"auth_token_file" => "/dev/null"}).clone
        auth_file_opts.delete("auth_token_env")
        auth_file_opts
      }

      context "both auth_token env and file are provided" do
        let(:opts) {default_opts.merge({"auth_token_file" => "/dev/null"})}
        include_examples("configuration errors")
      end

      context "neither auth_token env nor file are provided" do
        let(:opts) {
          opts = default_opts.clone
          opts.delete("auth_token_env")
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
        before {allow(File).to receive(:read).with(opts["auth_token_file"]) { raise IOError }}
        include_examples("configuration errors")
      end
      
      context "auth_token_env with invalid characters" do
        let(:opts) {default_opts.merge({"auth_token_env" => "%$%$%$%$%$"})}
        include_examples("configuration errors")
      end
    end
  end

  describe "instances" do
    subject { klass.new(default_opts) }

    before do
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
      instance.register
    end

    # context "given 'cron' expression" do
    #   let(:opts) { default_opts.merge("schedule" => {"cron" => "* * * * * UTC"}) }
    #   let(:instance) { klass.new(opts) }
    #   it "should run at the schedule" do
    #     Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
    #     Timecop.scale(61) # was previously 60
    #     queue = Queue.new
    #     runner = Thread.new do
    #       instance.run(queue)
    #     end
    #     sleep 3
    #     instance.stop
    #     runner.kill
    #     runner.join
    #     expect(queue.size).to eq(5) # was previously 2
    #     Timecop.return
    #   end
    # end

    # context "given 'at' expression" do
    #   let(:opts) { default_opts.merge("schedule" => {"at" => "2000-01-01 00:05:00 +0000"}) }
    #   let(:instance) { klass.new(opts) }
    #   it "should run at the schedule" do
    #     Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
    #     Timecop.scale(61 * 5) # was (60 * 5)
    #     queue = Queue.new
    #     runner = Thread.new do
    #       instance.run(queue)
    #     end
    #     sleep 2
    #     instance.stop
    #     runner.kill
    #     runner.join
    #     expect(queue.size).to eq(1)
    #     Timecop.return
    #   end
    # end

    # context "given 'every' expression" do
    #   let(:opts) { default_opts.merge("schedule" => {"every" => "2s"}) }
    #   let(:instance) { klass.new(opts) }
    #   it "should run at the schedule" do
    #     queue = Queue.new
    #     runner = Thread.new do
    #       instance.run(queue)
    #     end
    #     #T       0123456
    #     #events  x x x x
    #     #expects 3 events at T=5
    #     sleep 6 # was previously 5
    #     instance.stop
    #     runner.kill
    #     runner.join
    #     expect(queue.size).to eq(3)
    #   end
    # end

    # context "given 'in' expression" do
    #   let(:opts) { default_opts.merge("schedule" => {"in" => "2s"}) }
    #   let(:instance) { klass.new(opts) }
    #   it "should run at the schedule" do
    #     queue = Queue.new
    #     runner = Thread.new do
    #       instance.run(queue)
    #     end
    #     sleep
    #     instance.stop
    #     runner.kill
    #     runner.join
    #     expect(queue.size).to eq(1)
    #   end
    # end
  end

  describe "events" do
    shared_examples("matching metadata") {
      let(:metadata) { event.get(metadata_target) }
      let(:options) { defined?(settings) ? settings : opts }
      # The URL gets modified b/c of the limit that is placed on the API
      let(:metadata_url) { "#{options["url"]}?limit=#{options["chunk_size"]}" }
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
        poller.register
        allow(poller).to receive(:handle_failure).and_call_original
        allow(poller).to receive(:handle_success)
        event # materialize the subject
      end

      it "should enqueue a message" do
        expect(event).to be_a(LogStash::Event)
      end

      it "should enqueue a message with 'http_request_failure' set" do
        expect(event.get("http_request_failure")).to be_a(Hash)
      end

      it "should tag the event with '_http_request_failure'" do
        expect(event.get("tags")).to include('_http_request_failure')
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
      context "due to a non-existent host" do # Fail with handlers
        let(:url) { "http://thouetnhoeu89ueoueohtueohtneuohn" }
        let(:code) { nil } # no response expected

        let(:settings) { default_opts.merge("url" => url) }

        include_examples("unprocessable_requests")
      end

      context "due to a bogus port number" do # fail with return?
        let(:invalid_port) { Flores::Random.integer(65536..1000000) }

        let(:url) { "http://127.0.0.1:#{invalid_port}" }
        let(:settings) { default_opts.merge("url" => url) }
        let(:code) { nil } # No response expected

        include_examples("unprocessable_requests")
      end
    end

    describe "a valid request and decoded response" do
      # let(:payload) {{"a" => 2, "hello" => ["a", "b", "c"]}}
      # let(:response_body) { LogStash::Json.dump(payload) }
      # let(:code) { 200 }
      # let(:url) { default_url }

      # let(:opts) { default_opts }
      # let(:instance) {
      #   klass.new(opts)
      # }

      # subject(:event) {
      #   queue.pop(true)
      # }

      # before do
      #   instance.register
      #   allow(instance).to receive(:decorate)
      #   instance.client.stub(%r{#{url}.*}, 
      #                        :body => response_body,
      #                        :code => code
      #   )

      #   instance.send(:run_once, queue)
      # end

      # it "should have a matching message" do
      #   expect(event.to_hash).to include(payload)
      # end

      # it "should decorate the event" do
      #   expect(instance).to have_received(:decorate).once
      # end

      # include_examples("matching metadata")
      
      # context "with an empty body" do
      #   let(:response_body) { "" }
      #   it "should return an empty event" do
      #     instance.send(:run_once, queue)
      #     expect(event.get("[_http_poller_metadata][response_headers][content-length]")).to eql("0")
      #   end
      # end

      # context "with metadata omitted" do
      #   let(:opts) {
      #     opts = default_opts.clone
      #     opts.delete("metadata_target")
      #     opts
      #   }

      #   it "should not have any metadata on the event" do
      #     instance.send(:run_once, queue)
      #     expect(event.get(metadata_target)).to be_nil
      #   end
      # end

      # context "with a specified target" do
      #   let(:target) { "mytarget" }
      #   let(:opts) { default_opts.merge("target" => target) }

      #   it "should store the event info in the target" do
      #     # When events go through the pipeline they are java-ified
      #     # this normalizes the payload to java types
      #     payload_normalized = LogStash::Json.load(LogStash::Json.dump(payload))
      #     expect(event.get(target)).to include(payload_normalized)
      #   end
      # end

      # context "with non-200 HTTP response codes" do
      #   let(:code) { |example| example.metadata[:http_code] }
      #   let(:response_body) { "{}" }

      #   it "responds to a 500 code", :http_code => 500 do
      #     instance.send(:run_once, queue)
      #     expect(event.to_hash).to include({"HTTP-Code" => 500})
      #     expect(event.get("tags")).to include('_okta_response_error')
      #   end
      #   it "responds to a 401/Unauthorized code", :http_code => 401 do
      #     instance.send(:run_once, queue)
      #     expect(event.to_hash).to include({"HTTP-Code" => 401})
      #     expect(event.get("tags")).to include('_okta_response_error')
      #   end
      #   it "responds to a 400 code", :http_code => 400 do
      #     instance.send(:run_once, queue)
      #     expect(event.to_hash).to include({"HTTP-Code" => 400})
      #     expect(event.get("tags")).to include('_okta_response_error')
      #   end
      #   context "specific okta errors" do
      #     let(:payload) { {:okta_error => "E0000031" } }
      #     let(:response_body) { LogStash::Json.dump(payload) }

      #     it "responds to a filter string error", :http_code => 400 do
      #       expect(event.to_hash).to include({"HTTP-Code" => 400})
      #       expect(event.to_hash).to include({"Okta-Plugin-Status" => "Filter string was not valid."})
      #       expect(event.get("tags")).to include('_okta_response_error')
      #     end
      #   end
      # end
    end
  end

  describe "stopping" do
    let(:config) { default_opts }
    it_behaves_like "an interruptible input plugin"
  end

  describe "state file" do
    # context "when being setup" do

    #   let(:opts) { default_opts.merge({'state_file_base' => "/tmp/okta_test_"}) }
    #   subject { klass.new(opts) }

    #   let(:state_file_url) { "http://localhost:38432/?limit=1000&after=asdfasdf" }
    #   let(:state_file_url_b64) { Base64.urlsafe_encode64(state_file_url) }
    #   let(:test_url) { "#{opts["url"]}?limit=#{opts["chunk_size"]}" }
    #   let(:state_file_url_changed) { "http://example.com/?limit=1000" }
    #   let(:state_file_url_changed_b64) { Base64.urlsafe_encode64(state_file_url_changed) }

    #   it "creates the file correctly" do
    #     expect(File).to receive(:open).with("#{opts['state_file_base']}start","w") {}
    #     subject.register
    #   end

    #   it "checks the file checks are running" do
    #     #expect(File).to receive(:readable?).with(File.dirname(opts['state_file_base']))
    #     allow(File).to receive(:readable?).with(File.dirname(opts['state_file_base'])) { false }
    #     allow(File).to receive(:executable?).with(File.dirname(opts['state_file_base'])) { false }
    #     allow(File).to receive(:writable?).with(File.dirname(opts['state_file_base'])) { false }
    #     expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
    #   end

    #   it "raises an error on file creation" do
    #     allow(File).to receive(:open).with("#{opts['state_file_base']}start","w") { raise IOError }
    #     expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
    #   end

    #   it "raises exception when there is more than one file" do
    #     allow(File).to receive(:open).with("#{opts['state_file_base']}start","w") {}
    #     allow(Dir).to receive(:[]) { ["#{opts['state_file_base']}1","#{opts['state_file_base']}2"] }
    #     expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
    #   end

    #   it "creates a url based on the state file" do
    #     allow(Dir).to receive(:[]) { [opts['state_file_base'] + state_file_url_b64] }
    #     subject.register
    #     expect(subject.instance_variable_get("@url")).to eql(state_file_url)
    #   end

    #   it "uses the URL from options when state file is in a start state" do
    #     allow(Dir).to receive(:[]) { [opts['state_file_base'] + "start"] }
    #     subject.register
    #     expect(subject.instance_variable_get("@url").to_s).to eql(test_url)
    #   end

    #   it "raises an error when the config url is not part of the saved state" do
    #     allow(Dir).to receive(:[]) { [opts['state_file_base'] + state_file_url_changed_b64] }
    #     expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
    #   end
    # end
    
    # context "when running" do
    #   let(:opts) { default_opts.merge({'state_file_base' => "/tmp/okta_test_"}) }
    #   let(:instance) { klass.new(opts) }

    #   let(:payload) { '[{"eventId":"tevIMARaEyiSzm3sm1gvfn8cA1479235809000"}]}]' }
    #   let(:response_body) { LogStash::Json.dump(payload) }
      
    #   let(:url_initial) { "http://localhost:38432/events?after=1" }
    #   let(:url_initial_b64) { Base64.urlsafe_encode64(url_initial) }
    #   let(:url_final) { "http://localhost:38432/events?after=2" }
    #   let(:url_final_b64) { Base64.urlsafe_encode64(url_final) }
    #   let(:headers) { {"link" => ["<#{url_initial}>; rel=\"self\"", "<#{url_final}>; rel=\"next\""]} }
    #   let(:code) { 200 }

    #   before(:each) do |example|
    #     allow(Dir).to receive(:[]) { [opts['state_file_base'] + url_initial_b64] }

    #     instance.register
    #     instance.client.stub( url_initial,
    #       :headers => headers,
    #       :body => response_body,
    #       :code => code )

    #     allow(instance).to receive(:handle_failure) { instance.instance_variable_set(:@continue,false) }
    #   end

    #   it "updates the state file after data is fetched" do
    #     expect(File).to receive(:rename).with(opts['state_file_base'] + url_initial_b64, opts['state_file_base'] + url_final_b64) { 0 }
    #     instance.client.stub( url_final,
    #       :headers => {:link => "<#{url_final}>; rel=\"self\""},
    #       :body => "{}",
    #       :code => code )
    #     instance.send(:run_once, queue)
    #   end

    #   it "updates the state file after a failure" do
    #     expect(File).to receive(:rename).with(opts['state_file_base'] + url_initial_b64, opts['state_file_base'] + url_final_b64) { 0 }
    #     instance.send(:run_once, queue)
    #   end
      
    #   context "when stop is called" do
    #     it "saves the state in the file" do
    #       # We are still testing the same condition, file renaming.
    #       expect(File).to receive(:rename).with(opts['state_file_base'] + url_initial_b64, opts['state_file_base'] + url_final_b64) { 0 }

    #       # Force a sleep to make the thread hang in the failure condition.
    #       allow(instance).to receive(:handle_failure) {
    #         instance.instance_variable_set(:@continue,false)
    #         sleep(30)
    #         }

    #       plugin_thread = Thread.new(instance,queue) { |subject, queue| instance.send(:run, queue) }

    #       # Sleep for a bit to make sure things are started.
    #       sleep 0.5
    #       expect(plugin_thread).to be_alive

    #       instance.do_stop

    #       # As they say in the logstash thread, why 3?
    #       # Because 2 is too short, and 4 is too long.
    #       wait(3).for { plugin_thread }.to_not be_alive
    #     end
    #   end
    # end
  end


end
