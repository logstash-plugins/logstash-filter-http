require 'logstash/devutils/rspec/spec_helper'
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require 'logstash/filters/http'

describe LogStash::Filters::Http do
  subject { described_class.new(config) }
  let(:event) { LogStash::Event.new(data) }
  let(:data) { { "message" => "test" } }

  let(:url) { 'https://a-non-existent.url1' }
  let(:config) { { "url" => url, 'target_body' => '[the][body]' } }

  let(:response) { [200, {}, "Bom dia"] }

  describe 'target_body default', :ecs_compatibility_support do

    let(:config) { { "url" => url, "ecs_compatibility" => ecs_compatibility } }

    ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

      it "has a default body_target (in legacy mode)" do
        subject.register
        allow(subject).to receive(:request_http).and_return(response)
        subject.filter(event)

        expect(event.get('body')).to eq("Bom dia")
      end if ecs_select.active_mode == :disabled

      it "fails due missing body_target (in ECS mode)" do
        expect { subject }.to raise_error(LogStash::ConfigurationError)
      end if ecs_select.active_mode != :disabled

    end

  end

  describe 'response body handling', :ecs_compatibility_support do

    let(:url) { 'http://laceholder.typicode.com/users/10' }

    before(:each) do
      subject.register

      allow(subject).to receive(:request_http).and_return(response)
      subject.filter(event)
    end

    ecs_compatibility_matrix(:disabled, :v1, :v8) do

      let(:config) { super().merge "ecs_compatibility" => ecs_compatibility, 'target_body' => 'gw-response' }

      context "when body is JSON" do
        context "and headers are set correctly" do

          let(:response) { [200, {"content-type" => "application/json"}, "{\"id\": 10}"] }

          it "fetches and writes body to target" do
            expect(event.get('[gw-response][id]')).to eq(10)
          end

        end
      end

      context "when there is no body" do
        let(:response) { [204, {}, nil] }

        it "doesn't write a body to the event" do
          expect(event.get('[gw-response]')).to be_nil
        end
      end

      context 'with body target' do

        let(:config) { super().merge "target_body" => '[rest]' }

        it "fetches and writes body to target" do
          expect(event.get('rest')).to eq("Bom dia")
          expect(event.include?('body')).to be false
        end

      end

    end
  end

  describe 'URL parameter' do
    before(:each) { subject.register }
    context "when url contains field references" do
      let(:config) do
        { "url" => "http://stringsize.com/%{message}", "target_body" => "size" }
      end
      let(:response) { [200, {}, "4"] }

      it "interpolates request url using event data" do
        expect(subject).to receive(:request_http).with(anything, "http://stringsize.com/test", anything).and_return(response)
        subject.filter(event)
        expect(event.get('size')).to eql '4'
      end
    end
  end
  context 'when request returns 404' do
    before(:each) { subject.register }
    let(:config) do
      {
        'url' => 'http://httpstat.us/404',
        'target_body' => 'rest'
      }
    end
    let(:response) { [404, {}, ""] }

    before(:each) do
      allow(subject).to receive(:request_http).and_return(response)
      subject.filter(event)
    end

    it "tags the event with _httprequestfailure" do
      expect(event).to_not include('rest')
      expect(event.get('tags')).to include('_httprequestfailure')
    end
  end

  describe "headers", :ecs_compatibility_support do
    before(:each) { subject.register }
    let(:response) do
      response_headers = {
          'Server' => 'Apache',
          'Last-Modified' => 'Mon, 18 Jul 2016 02:36:04 GMT',
          'X-Backend-Server' => 'logstash.elastic.co',
          'Content-Type' => %w[application/json application/xml]
      }
      [200, response_headers, "Bom dia"]
    end

    let(:url) { "http://stringsize.com" }

    ecs_compatibility_matrix(:disabled, :v1) do |ecs_select|

      let(:config) { super().merge "ecs_compatibility" => ecs_compatibility }

      it "sets response headers in the event" do
        expect(subject).to receive(:request_http).with(anything, config['url'], anything).and_return(response)

        subject.filter(event)

        if ecs_select.active_mode == :disabled
          expect(event.get('headers')).to include "Server" => "Apache"
          expect(event.get('headers')).to include "X-Backend-Server" => "logstash.elastic.co"
          expect(event.get('headers')).to include "Content-Type" => %w[application/json application/xml]
        else
          expect(event.include?('headers')).to be false
          expect(event.get('[@metadata][filter][http][response][headers]')).to include "Server" => "Apache"
          expect(event.get('[@metadata][filter][http][response][headers]')).to include "X-Backend-Server" => "logstash.elastic.co"
          expect(event.get('[@metadata][filter][http][response][headers]')).to include "Content-Type" => %w[application/json application/xml]
        end
      end

      context 'with a headers target' do

        let(:config) { super().merge "target_headers" => '[res][headers]' }

        it "sets response headers in the event" do
          expect(subject).to receive(:request_http).with(anything, config['url'], anything).and_return(response)

          subject.filter(event)

          expect(event.get('[res][headers]')).to include "Server" => "Apache"
          expect(event.get('[res][headers]').keys).to include "Last-Modified"
        end

      end

    end

    context "(extra) request headers" do
      let(:headers) { { "Cache-Control" => "nocache" } }
      let(:config) { super().merge "headers" => headers }

      it "are included in the request" do
        expect(subject).to receive(:request_http) do |verb, url, options|
          expect( options.fetch(:headers, {}) ).to include(headers)
        end.and_return(response)

        subject.filter(event)
      end
    end

    context "content-type header" do
      let(:config) { super().merge "headers" => headers }

      describe 'when content-type header is an array' do
        let(:headers) {{ "Content-type" => %w[application/json logstash/custom-media-type] }}

        it "resolves the content-type" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect( options.fetch(:headers, {}) ).to include(headers)
          end.and_return(response)

          expect{ subject.filter(event) }.not_to raise_error
        end
      end

      describe 'when content-type header is a string' do
        let(:headers) {{ "Content-type" => "application/json; logstash/custom-media-type" }}

        it "resolves the content-type" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect( options.fetch(:headers, {}) ).to include(headers)
          end.and_return(response)

          expect{ subject.filter(event) }.not_to raise_error
        end
      end

      describe 'when content-type header is an empty string' do
        let(:headers) {{ "Content-type" => "" }}

        it "resolves the content-type" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect( options.fetch(:headers, {}) ).to include(headers)
          end.and_return(response)

          expect{ subject.filter(event) }.not_to raise_error
        end
      end
    end
  end

  describe "query string parameters" do
    before(:each) { subject.register }
    let(:response) { [200, {}, "Bom dia"] }
    context "when set" do
      let(:query) { { "color" => "green" } }
      let(:config) { super().merge "query" => query }

      it "are included in the request" do
        expect(subject).to receive(:request_http).with(anything, anything, include(:query => query)).and_return(response)
        subject.filter(event)
      end
    end
  end
  describe "request body" do
    before(:each) { subject.register }
    let(:response) { [200, {}, "Bom dia"] }
    let(:url) { "http://stringsize.com" }

    describe "format" do
      let(:config) { super().merge "body_format" => body_format, "body" => body }

      context "when is json" do
        let(:body_format) { "json" }
        let(:body) do
          { "hey" => "you" }
        end
        let(:body_json) { LogStash::Json.dump(body) }

        it "serializes the body to json" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect(options).to include(:body => body_json)
          end.and_return(response)
          subject.filter(event)
        end

        it "sets content-type to application/json" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect(options).to include(:headers => { "content-type" => "application/json"})
          end.and_return(response)
          subject.filter(event)
        end

      end
      context "when is text" do
        let(:body_format) { "text" }
        let(:body) { "Hey, you!" }

        it "uses the text as body for the request" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect(options).to include(:body => body)
          end.and_return(response)
          subject.filter(event)
        end

        it "sets content-type to text/plain" do
          expect(subject).to receive(:request_http) do |verb, url, options|
            expect(options).to include(:headers => { "content-type" => "text/plain"})
          end.and_return(response)
          subject.filter(event)
        end

        context 'content-type header present' do

          let(:config) { super().merge 'headers' => { 'X-UA' => 'FOO', 'Content-Type' => 'application/x-www-form-urlencoded' } }

          it "respects set header and does not add another" do
            expect(subject).to receive(:request_http) do |verb, url, options|
              headers = options[:headers]
              expect(headers).to include("Content-Type" => "application/x-www-form-urlencoded")
              expect(headers).to_not include("content-type")
            end.and_return(response)
            subject.filter(event)
          end

        end

      end
    end
    context "when using field references" do
      let(:body_format) { "json" }
      let(:body) do
        { "%{key1}" => [ "%{[field1]}", "another_value", { "key" => "other-%{[nested][field2]}" } ] }
      end
      let(:body_json) { LogStash::Json.dump(body) }
      let(:data) do
        {
          "message" => "ola",
          "key1" => "mykey",
          "field1" => "normal value",
          "nested" => { "field2" => "value2" }
        }
      end

      it "fills the body with event data" do
        expect(subject).to receive(:request_http) do |verb, url, options|
          body = options.fetch(:body, {})
          expect(body.keys).to include("mykey")
          expect(body.fetch("mykey")).to eq(["normal value", "another_value", { "key" => "other-value2" }])
        end.and_return(response)
        subject.filter(event)
      end
    end
    context "when the verb is HEAD" do
      let(:config) { super().merge("verb" => "HEAD") }
      before(:each) do
        allow(subject).to receive(:request_http).and_return(response)
      end
      it "does not include the body" do
        subject.filter(event)
        expect(event).to_not include("body")
      end
    end
  end
  describe "verb" do
    let(:response) { [200, {}, "Bom dia"] }
    let(:config) { super().merge "verb" => verb }

    ["GET", "HEAD", "POST", "DELETE", "PATCH", "PUT"].each do |verb_string|
      let(:verb) { verb_string }
      context "when verb #{verb_string} is set" do
        before(:each) { subject.register }
        it "it is used in the request" do
          expect(subject).to receive(:request_http).with(verb.downcase, anything, anything).and_return(response)
          subject.filter(event)
        end
      end
    end
    context "when using an invalid verb" do
      let(:verb) { "something else" }
      it "it is used in the request" do
        expect { described_class.new(config) }.to raise_error ::LogStash::ConfigurationError
      end
    end
  end
end

describe "obsolete settings" do
  let(:url) { 'https://a-non-existent.url1' }
  let(:config) { { "url" => url, 'target_body' => '[the][body]' } }

  [{:name => 'cacert', :canonical_name => 'ssl_certificate_authorities'},
   {:name => 'client_cert', :canonical_name => 'ssl_certificate'},
   {:name => 'client_key', :canonical_name => 'ssl_key'},
   {:name => "keystore", :canonical_name => 'ssl_keystore_path'},
   {:name => 'truststore', :canonical_name => 'ssl_truststore_path'},
   {:name => "keystore_password", :canonical_name => "ssl_keystore_password"},
   {:name => 'truststore_password', :canonical_name => "ssl_truststore_password"},
   {:name => "keystore_type", :canonical_name => "ssl_keystore_type"},
   {:name => 'truststore_type', :canonical_name => 'ssl_truststore_type'}
  ].each do |settings|
    context "with option #{settings[:name]}" do
      let(:obsolete_config) { config.merge(settings[:name] => 'test_value') }

      it "emits an error about the setting `#{settings[:name]}` now being obsolete and provides guidance to use `#{settings[:canonical_name]}`" do
        error_text = /The setting `#{settings[:name]}` in plugin `http` is obsolete and is no longer available. Use `#{settings[:canonical_name]}` instead/i
        expect { LogStash::Filters::Http.new(obsolete_config) }.to raise_error LogStash::ConfigurationError, error_text
      end

    end
  end
end
=begin
  # TODO refactor remaning tests to avoid whole pipeline instantiation
  describe 'empty response' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            params => {
              userId => 0
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => 'some text') do
      expect(subject).to_not include('rest')
      expect(subject.get('tags')).to include('_restfailure')
    end
  end
  describe 'Set to Rest Filter Get with params sprintf' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            params => {
              userId => "%{message}"
              id => "%{message}"
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          json => true
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => '1') do
      expect(subject).to include('rest')
      expect(subject.get('[rest][0]')).to include('userId')
      expect(subject.get('[rest][0][userId]')).to eq(1)
      expect(subject.get('[rest][0][id]')).to eq(1)
      expect(subject.get('rest').length).to eq(1)
      expect(subject.get('rest')).to_not include('fallback')
    end
  end
  describe 'Set to Rest Filter Post with params' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            method => 'post'
            params => {
              title => 'foo'
              body => 'bar'
              userId => 42
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          json => true
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => 'some text') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('id')
      expect(subject.get('[rest][userId]')).to eq(42)
      expect(subject.get('rest')).to_not include('fallback')
    end
  end
  describe 'Set to Rest Filter Post with params sprintf' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            method => 'post'
            params => {
              title => '%{message}'
              body => 'bar'
              userId => "%{message}"
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          json => true
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => '42') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('id')
      expect(subject.get('[rest][title]')).to eq(42)
      expect(subject.get('[rest][userId]')).to eq(42)
      expect(subject.get('rest')).to_not include('fallback')
    end
    sample('message' => ':5e?#!-_') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('id')
      expect(subject.get('[rest][title]')).to eq(':5e?#!-_')
      expect(subject.get('[rest][userId]')).to eq(':5e?#!-_')
      expect(subject.get('rest')).to_not include('fallback')
    end
    sample('message' => ':4c43=>') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('id')
      expect(subject.get('[rest][title]')).to eq(':4c43=>')
      expect(subject.get('[rest][userId]')).to eq(':4c43=>')
      expect(subject.get('rest')).to_not include('fallback')
    end
  end
  describe 'Set to Rest Filter Post with body sprintf' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            method => 'post'
            body => {
              title => 'foo'
              body => 'bar'
              userId => "%{message}"
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          json => true
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => '42') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('id')
      expect(subject.get('[rest][userId]')).to eq(42)
      expect(subject.get('rest')).to_not include('fallback')
    end
  end
  describe 'Set to Rest Filter Post with body sprintf nested params' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'https://jsonplaceholder.typicode.com/posts'
            method => 'post'
            body => {
              key1 => [
                {
                  "filterType" => "text"
                  "text" => "salmon"
                  "boolean" => false
                },
                {
                  "filterType" => "unique"
                }
              ]
              key2 => [
                {
                  "message" => "123%{message}"
                  "boolean" => true
                }
              ]
              key3 => [
                {
                  "text" => "%{message}123"
                  "filterType" => "text"
                  "number" => 44
                },
                {
                  "filterType" => "unique"
                  "null" => nil
                }
              ]
              userId => "%{message}"
            }
            headers => {
              'Content-Type' => 'application/json'
            }
          }
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => '42') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('key1')
      expect(subject.get('[rest][key1][0][boolean]')).to eq('false')
      expect(subject.get('[rest][key1][1][filterType]')).to eq('unique')
      expect(subject.get('[rest][key2][0][message]')).to eq('12342')
      expect(subject.get('[rest][key2][0][boolean]')).to eq('true')
      expect(subject.get('[rest][key3][0][text]')).to eq('42123')
      expect(subject.get('[rest][key3][0][filterType]')).to eq('text')
      expect(subject.get('[rest][key3][0][number]')).to eq(44)
      expect(subject.get('[rest][key3][1][filterType]')).to eq('unique')
      expect(subject.get('[rest][key3][1][null]')).to eq('nil')
      expect(subject.get('[rest][userId]')).to eq(42)
      expect(subject.get('rest')).to_not include('fallback')
    end
  end
  describe 'fallback' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'http://jsonplaceholder.typicode.com/users/0'
          }
          json => true
          fallback => {
            'fallback1' => true
            'fallback2' => true
          }
          target => 'rest'
        }
      }
    CONFIG
    end

    sample('message' => 'some text') do
      expect(subject).to include('rest')
      expect(subject.get('rest')).to include('fallback1')
      expect(subject.get('rest')).to include('fallback2')
      expect(subject.get('rest')).to_not include('id')
    end
  end
  describe 'empty target exception' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'http://jsonplaceholder.typicode.com/users/0'
          }
          json => true
          fallback => {
            'fallback1' => true
            'fallback2' => true
          }
          target => ''
        }
      }
    CONFIG
    end
    sample('message' => 'some text') do
      expect { subject }.to raise_error(LogStash::ConfigurationError)
    end
  end
  describe 'http client throws exception' do
    let(:config) do <<-CONFIG
      filter {
        rest {
          request => {
            url => 'invalid_url'
          }
          target => 'rest'
        }
      }
    CONFIG
    end
    sample('message' => 'some text') do
      expect(subject).to_not include('rest')
      expect(subject.get('tags')).to include('_restfailure')
    end
  end
end
=end
