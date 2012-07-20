require 'spec_helper'

describe JSON::JWK::Set do
  let(:jwk) { JSON::JWK.new public_key }
  let(:set) { JSON::JWK::Set.new jwk }

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