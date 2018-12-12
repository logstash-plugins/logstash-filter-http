require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/http'

describe LogStash::Filters::Http do
  subject { described_class.new(config) }
  let(:event) { LogStash::Event.new(data) }
  let(:data) { { "message" => "test" } }

  describe 'response body handling' do
    before(:each) { subject.register }
    let(:url) { 'http://laceholder.typicode.com/users/10' }
    let(:config) do
      { "url" => url, "target_body" => 'rest' }
    end
    before(:each) do
      allow(subject).to receive(:request_http).and_return(response)
      subject.filter(event)
    end

    context "when body is text" do
      let(:response) { [200, {}, "Bom dia"] }

      it "fetches and writes body to target" do
        expect(event.get('rest')).to eq("Bom dia")
      end
    end
    context "when body is JSON" do
      context "and headers are set correctly" do
        let(:response) { [200, {"content-type" => "application/json"}, "{\"id\": 10}"] }

        it "fetches and writes body to target" do
          expect(event.get('[rest][id]')).to eq(10)
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
  describe "headers" do
    before(:each) { subject.register }
    let(:response) { [200, {}, "Bom dia"] }
    context "when set" do
      let(:headers) { { "Cache-Control" => "nocache" } }
      let(:config) do
        {
          "url" => "http://stringsize.com",
          "target_body" => "size",
          "headers" => headers
        }
      end
      it "are included in the request" do
        expect(subject).to receive(:request_http) do |verb, url, options|
          expect(options.fetch(:headers, {})).to include(headers)
        end.and_return(response)
        subject.filter(event)
      end
    end
  end
  describe "query string parameters" do
    before(:each) { subject.register }
    let(:response) { [200, {}, "Bom dia"] }
    context "when set" do
      let(:query) { { "color" => "green" } }
      let(:config) do
        {
          "url" => "http://stringsize.com/%{message}",
          "target_body" => "size",
          "query" => query
        }
      end
      it "are included in the request" do
        expect(subject).to receive(:request_http).with(anything, anything, include(:query => query)).and_return(response)
        subject.filter(event)
      end
    end
  end
  describe "request body" do
    before(:each) { subject.register }
    let(:response) { [200, {}, "Bom dia"] }
    let(:config) do
      {
        "url" => "http://stringsize.com",
        "body" => body
      }
    end

    describe "format" do
      let(:config) do
        {
          "url" => "http://stringsize.com",
          "body_format" => body_format,
          "body" => body
        }
      end

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
  end
  describe "verb" do
    let(:response) { [200, {}, "Bom dia"] }
    let(:config) do
      {
        "verb" => verb,
        "url" => "http://stringsize.com",
        "target_body" => "size"
      }
    end
    ["GET", "HEAD", "POST", "DELETE"].each do |verb_string|
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

=begin
  # TODO refactor remaning tests to avoid insist + whole pipeline instantiation
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
