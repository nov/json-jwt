require 'spec_helper'

describe JSON::JWK::Set do
  let(:jwk) { public_key.to_jwk }
  let(:set) { JSON::JWK::Set.new jwk }

  describe '#content_type' do
    it do
      set.content_type.should == 'application/jwk-set+json'
    end
  end

  context 'when single JWK given' do
    subject { JSON::JWK::Set.new jwk }
    it { should == [jwk] }
  end

  context 'when multiple JWKs given' do
    subject { JSON::JWK::Set.new jwk, jwk }
    it { should == [jwk, jwk] }
  end

  context 'when an Array of JWKs given' do
    subject { JSON::JWK::Set.new [jwk, jwk] }
    it { should == [jwk, jwk] }
  end

  context 'when JSON::JWK given' do
    subject { JSON::JWK::Set.new jwk }

    it 'should keep JSON::JWK' do
      subject.each do |jwk|
        jwk.should be_instance_of JSON::JWK
      end
    end
  end

  context 'when pure Hash given' do
    subject { JSON::JWK::Set.new jwk.as_json }

    it 'should convert into JSON::JWK' do
      subject.each do |jwk|
        jwk.should be_instance_of JSON::JWK
      end
    end
  end

  context 'when pure Hash with :keys key given' do
    subject do
      JSON::JWK::Set.new(
        keys: jwk.as_json
      )
    end

    it 'should convert into JSON::JWK' do
      subject.each do |jwk|
        jwk.should be_instance_of JSON::JWK
      end
    end
  end

  describe '#as_json' do
    it 'should become proper JWK set format' do
      json = set.as_json
      json.should include :keys
      json[:keys].should == [jwk]
    end
  end

  describe '#to_json' do
    it do
      expect { set.to_json }.not_to raise_error
    end
  end
end