require 'spec_helper'

describe JSON::JWK::Set do
  let(:jwk) { JSON::JWK.new public_key }

  context 'when single JWK given' do
    let(:set) { JSON::JWK::Set.new jwk }

    it 'should become proper JWK set format' do
      _set_ = set.as_json
      _set_.should include :keys
      _set_[:keys].should == [jwk]
    end
  end

  context 'when multiple JWKs given' do
    let(:set) { JSON::JWK::Set.new jwk, jwk }

    it 'should become proper JWK set format' do
      _set_ = set.as_json
      _set_.should include :keys
      _set_[:keys].should == [jwk, jwk]
    end
  end

  context 'when an Array of JWKs given' do
    let(:set) { JSON::JWK::Set.new [jwk, jwk] }

    it 'should become proper JWK set format' do
      _set_ = set.as_json
      _set_.should include :keys
      _set_[:keys].should == [jwk, jwk]
    end
  end
end