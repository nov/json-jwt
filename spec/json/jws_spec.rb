require 'spec_helper'

describe JSON::JWS do
  let(:alg) { :none }
  let(:jwt) do
    _jwt_ = JSON::JWT.new claims
    _jwt_.alg = alg
    _jwt_
  end
  let(:jwt_blank) do
    _jwt_ = JSON::JWT.new nil
    _jwt_.alg = alg
    _jwt_
  end
  let(:jws) { JSON::JWS.new jwt }
  let(:jws_blank) { JSON::JWS.new jwt_blank }
  let(:signed) { jws.sign! private_key_or_secret }
  let(:signed_blank) { jws_blank.sign! private_key_or_secret }
  let(:decoded) { JSON::JWT.decode signed.to_s, public_key_or_secret }
  let(:decoded_blank) { JSON::JWT.decode signed_blank.to_s, public_key_or_secret, nil, nil, true }
  let(:claims) do
    {
      iss: 'joe',
      exp: 1300819380,
      :'http://example.com/is_root' => true
    }
  end
  let(:expected_signature) do
    {
      :HS256 => 'DyuTgO2Ggb5nrhkkhI-RjVYIBe3o8oL4ijkAn94YPxQ',
      :HS384 => 'a5-7rr61TG8Snv9xxJ7l064ky-SCq1Mswe9t8HEorvoc_nnfIeUy9WQCLMIli34R',
      :HS512 => 'ce-GlHDaNwaHfmAFRGp3QPPKvrpruTug2hC1bf6yNlbuvkMwJw2jFZgq_4wmIPetRdiBy7XFq7rrtmw1Im7tmQ',
      :RS256 => 'E5VELqAdla2Bx1axc9KFxO0EiCr0Mw6HPYX070qGQ8zA_XmyxGPUZLyyWU_6Cn399W-oYBWO2ynLlr8pqqjP3jXevyCeYeGRVN0HzLYiBebEugNnc3hevr7WV2UzfksWRA-Ux2bDv2sz9p_LGbL33wWNxGDvIlpDyZUul_a48nCipS0riBjkTLTSE8dfBxQTXEF5GEUUu99ot6aBLzUhc25nHXSXogXF6MHK-hAcE7f4v-vJ0lbPbHLVGUopIoxoqe4XjoBpzE5UvhrVl5LYbdjbyJhu5ZIA8GLsgwtUFh3dfdIechORoR3k5NSFSv8157bAEa8t4iwgWD2MSNSQnw',
      :RS384 => 'lT5JbytGKgG9QrwkJuxgw7UjmN9tjkEQW9pVGR2XnKEdC0_wLNIzAmT-jTwyMDGBLUkWO7opDOP6Xy6_DOTg58k9PwVkyQzrLnmxJMEng2Q-aMqcitRSIvUk3DPy8kemp8yUPls9NzWmByM2GoUVHbDsR0r-tZN-g_9QYev32mvMhjMr30JI5S2xiRjc9m2GAaXMOQmNTovJgV4bgCp4UjruCrA0BD1JJwDqKYoR_YYr_ALcVjD_LUgy80udJvbi8MAYJVUf0QYtQDrX2wnT_-eiiWjD5XafLuXEQVDRh-v2MKAwdvtXMq5cZ08Zjl2SyHxJ3OqhEeWPvYGltxZh_A',
      :RS512 => 'EHeGM2Mo3ghhUfSB99AlREehrbC6OPE-nYL_rwf88ysTnJ8L1QQ0UuCrXq4SpRutGLK_bYTK3ZALvFRPoOgK_g0QWmqv6qjQRU_QTxoq8y8APP-IgKKDuIiGH6daBV2rAPLDReqYNKsKjmTvZJo2c0a0e_WZkkj_ZwpgjTG3v0gW9lbDAzLJDz18eqtR4ZO7JTu_fyNrUrNk-w2_wpxSsn9sygIMp0lKE0_pt0b01fz3gjTDjlltU0cKSalUp4geaBDH7QRcexrolIctdQFbNKTXQxoigxD3NLNkKGH7f6A8KZdcOm8AnEjullcZs8_OWGnW43p1qrxoBRSivb9pqQ'
    }
  end
  let(:expected_signature_blank_payload) do
    {
      :HS256 => 'iRFMM3GknVfzRTxlVQT87jfIw32Ik3lUYNGePPk5wnM',
      :HS384 => 'rxyzr3I2RWRBgQaewQt3yjdp3BqkrFh-iHcet318OYHWhXvyzAE0npf0l0xi5DOV',
      :HS512 => 'VDHOrPYrwycjaKbwccObXi6dmw4fVFqiFsNFQjqYHQAkxJGxqhfVLc1_WfKMa6C7vGSGroabaVdK7nn08XPdSQ',
      :RS256 => 'WthQjouPVbErM7McwSY4slJjHaWqmFg1qKdmTDvttkiyAEcTjVViJkNHH9Mp573h13cXtLob1xh3UJYh5_-hSA4Y24zdyck3jp3fsOusflp1cMmhWXZ2nETKeWCEJDKRAnWynHqkwes7tgWmS0gVeuljeNkuovJlHmNRcoMR9Z3ZuiHfc2WFh-iFbM5Zne1y-_SSgAZwOD20P0Ysn28DtJTlXcm74ENqhLEJnvHS-872d6surb23kHMns43GtT5bm-aJoMLct0nO1GBapQAiKUknTsw24IfOkX4vJNQzIWVSzx3zOxXjcVHlH92af6NknIlPCfRparLC9YEK2NkJYg',
      :RS384 => 'Jy6XNLNAyujRHYoCOtFqu7z0imHZMiwkwBr73ok_DDSDxQSA9ryt_q_tX0u8knpAIRcTJuNA0-s5DkGbpIj9coKgZ5JBvE_n9ijvNubImf8_vCDDitJemzUtnJypb9GbP4A3nWDAZC0KONVqlxpy92-9xrG5sFEzaYCFYZYnXv8kmmQEIVI1GXw4_Fx8HxRu5cae9WWTgaKQOFG54S303C0H966C1o6d9o3HQH7x8GEl632qBw4LzONWr_QpCN-UFgmJHO7yBwaP-RWnLDW3hYlb4IybRIvMQQicjkjNaNwLTmwo31orVxO53GcSjyhU2y_R843nQcNjTT_lD1QRvg',
      :RS512 => 'ws2HZ6wvh8GMrFKiIHXDogyx8HFpa4wvrLxfZaMfCoMPf0SZ4V3tiEZRWfrxyvwpsdBj2Mgm5lt3IYAHhlI2hqWvuikDq6tuViloaAIm2xwTU060bF0GL1tQJ-h20wUukJ6fsWet8M9DNg7hcElYQMawHhk4L91YUtY2hKT_uWgPih_pn0Hq5Ve0at4CwAyXXTwCYSEH23PMsUdDfE5tfCyvL2bNQ71Ld_MvQS1NLS7hydzEtfxLK-UkDQVclFmEM3JXrPG7YSRodtKlwJ-ESDx6CaJXXDAgitSF32dslcIkmOXRJqjNmF15i_aVg0ExiU92WTpCrdwzWTt4Aphqlw',
    }
  end

  shared_examples_for :jwt_with_alg do
    it { should == jwt }
    its(:header) { should == jwt.header }
  end

  context 'before sign' do
    subject { jws }
    it_behaves_like :jwt_with_alg
    its(:signature) { should be_nil }
  end

  describe '#content_type' do
    it do
      jws.content_type.should == 'application/jose'
    end
  end

  describe 'decode' do
    let(:alg) { :RS256 }
    let(:private_key_or_secret) { private_key }
    let(:public_key_or_secret) { public_key }

    describe 'blank payload not allowed' do
      it 'should raise format error' do
        expect do
          JSON::JWT.decode signed_blank.to_s, public_key_or_secret
        end.to raise_error JSON::JWT::InvalidFormat
      end
    end
    describe 'blank payload allowed' do
      it 'should not raise an error' do
        expect do
          JSON::JWT.decode signed_blank.to_s, public_key_or_secret, nil, nil, true
        end.to_not raise_error
      end
    end
  end

  describe '#sign!' do
    shared_examples_for :generate_expected_signature do
      it do
        Base64.urlsafe_encode64(signed.signature, padding: false).should == expected_signature[alg]
      end
      context 'with blank payload' do
        it do
          Base64.urlsafe_encode64(signed_blank.signature, padding: false).should == expected_signature_blank_payload[alg]
        end
      end
    end
    subject { signed }

    [:HS256, :HS384, :HS512].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }

        context 'when String key given' do
          let(:private_key_or_secret) { shared_secret }
          it_behaves_like :jwt_with_alg
          it_behaves_like :generate_expected_signature
        end

        context 'when JSON::JWK key given' do
          let(:private_key_or_secret) { JSON::JWK.new shared_secret }
          it_behaves_like :jwt_with_alg
          it_behaves_like :generate_expected_signature
        end
      end
    end

    [:RS256, :RS384, :RS512].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }

        context 'when OpenSSL::PKey::RSA key given' do
          let(:private_key_or_secret) { private_key }
          it_behaves_like :jwt_with_alg
          it_behaves_like :generate_expected_signature
        end

        context 'when JSON::JWK key given' do
          let(:private_key_or_secret) { JSON::JWK.new private_key }
          it_behaves_like :jwt_with_alg
          it_behaves_like :generate_expected_signature
        end
      end
    end

    [:ES256, :ES384, :ES512, :ES256K].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }

        shared_examples_for :self_verifiable do
          it 'should be self-verifiable' do
            expect do
              JSON::JWT.decode(
                JSON::JWT.new(claims).sign(
                  private_key_or_secret, algorithm
                ).to_s, public_key_or_secret
              )
            end.not_to raise_error
          end
        end

        context 'when OpenSSL::PKey::EC key given' do
          let(:private_key_or_secret) { private_key :ecdsa, digest_length: algorithm.to_s[2,3].to_i }
          let(:public_key_or_secret)  { public_key  :ecdsa, digest_length: algorithm.to_s[2,3].to_i }
          it_behaves_like :jwt_with_alg
          it_behaves_like :self_verifiable
        end

        context 'when JSON::JWK key given' do
          let(:private_key_or_secret) { JSON::JWK.new(private_key :ecdsa, digest_length: algorithm.to_s[2,3].to_i) }
          let(:public_key_or_secret)  { JSON::JWK.new(public_key  :ecdsa, digest_length: algorithm.to_s[2,3].to_i) }
          it_behaves_like :jwt_with_alg
          it_behaves_like :self_verifiable
        end
      end
    end

    context 'when JSON::JWK::Set key given' do
      let(:alg) { :HS256 }
      let(:kid) { 'kid' }
      let(:jwks) do
        jwk = JSON::JWK.new shared_secret, kid: kid
        JSON::JWK::Set.new jwk, JSON::JWK.new('another')
      end
      let(:signed) { jws.sign!(jwks) }

      context 'when jwk is found by given kid' do
        before { jws.kid = kid }
        it { should == jws.sign!('secret') }
      end

      context 'otherwise' do
        it do
          expect do
            subject
          end.to raise_error JSON::JWK::Set::KidNotFound
        end
      end
    end

    describe 'unknown algorithm' do
      let(:alg) { :unknown }
      it do
        expect do
          jws.sign! 'key'
        end.to raise_error JSON::JWS::UnexpectedAlgorithm
      end
    end
  end

  describe '#verify!' do
    shared_examples_for :success_signature_verification do
      it do
        expect { decoded }.not_to raise_error
        decoded.should be_a JSON::JWT
      end

      describe 'header' do
        let(:header) { decoded.header }
        it 'should be parsed successfully' do
          header[:typ].should == 'JWT'
          header[:alg].should == alg.to_s
        end
      end

      describe 'claims' do
        it 'should be parsed successfully' do
          decoded[:iss].should == 'joe'
          decoded[:exp].should == 1300819380
          decoded[:'http://example.com/is_root'] == true
        end
      end

      context 'with blank payload' do
        it do
          expect { decoded_blank }.not_to raise_error
          decoded_blank.should be_a JSON::JWT
        end

        describe 'header' do
          let(:header) { decoded_blank.header }
          it 'should be parsed successfully' do
            header[:typ].should == 'JWT'
            header[:alg].should == alg.to_s
          end
        end

        describe 'claims' do
          it 'should be parsed successfully' do
            p decoded_blank.blank_payload
            decoded_blank.blank_payload.should == true
            decoded_blank[:iss].should == nil
            decoded_blank[:exp].should == nil
            decoded[:'http://example.com/is_root'] == nil
          end
        end
      end

    end
    subject { decoded }

    [:HS256, :HS384, :HS512].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }
        let(:private_key_or_secret) { shared_secret }

        context 'when String key given' do
          let(:public_key_or_secret) { shared_secret }
          it_behaves_like :success_signature_verification
        end

        context 'when JSON::JWK key given' do
          let(:public_key_or_secret) { JSON::JWK.new shared_secret }
          it_behaves_like :success_signature_verification
        end
      end
    end

    [:RS256, :RS384, :RS512].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }
        let(:private_key_or_secret) { private_key }

        context 'when OpenSSL::PKey::RSA key given' do
          let(:public_key_or_secret) { public_key }
          it_behaves_like :success_signature_verification
        end

        context 'when JSON::JWK key given' do
          let(:public_key_or_secret) { JSON::JWK.new public_key }
          it_behaves_like :success_signature_verification
        end
      end
    end

    [:ES256, :ES384, :ES512, :ES256K].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }
        let(:private_key_or_secret) { private_key :ecdsa, digest_length: algorithm.to_s[2,3].to_i }

        context 'when OpenSSL::PKey::EC key given' do
          let(:public_key_or_secret) { public_key :ecdsa, digest_length: algorithm.to_s[2,3].to_i }
          it_behaves_like :success_signature_verification
        end

        context 'when JSON::JWK key given' do
          let(:public_key_or_secret) { JSON::JWK.new public_key(:ecdsa, digest_length: algorithm.to_s[2,3].to_i) }
          it_behaves_like :success_signature_verification
        end
      end
    end

    context 'when JSON::JWK::Set key given' do
      subject { JSON::JWT.decode signed.to_s, jwks }

      let(:alg) { :HS256 }
      let(:kid) { 'kid' }
      let(:jwks) do
        jwk = JSON::JWK.new shared_secret, kid: kid
        JSON::JWK::Set.new jwk, JSON::JWK.new('another')
      end
      let(:signed) { jws.sign!(jwks) }

      context 'when jwk is found by given kid' do
        before { jws.kid = kid }
        it { should == signed }
      end

      context 'otherwise' do
        it do
          expect do
            subject
          end.to raise_error JSON::JWK::Set::KidNotFound
        end
      end
    end

    describe 'unknown algorithm' do
      let(:alg) { :unknown }
      it do
        expect do
          jws.verify! 'key'
        end.to raise_error JSON::JWS::UnexpectedAlgorithm
      end
    end
  end

  describe '#to_json' do
    let(:alg) { :RS256 }
    let(:private_key_or_secret) { private_key }

    context 'as default' do
      it 'should JSONize payload' do
        jws.to_json.should == claims.to_json
      end
    end
    context 'with blank payload' do
      it 'should JSONize payload' do
        puts ("jws_blank: #{jws_blank.to_json.inspect}")
        jws_blank.to_json.should == ''
      end
    end

    context 'when syntax option given' do
      context 'when general' do
        it 'should return General JWS JSON Serialization' do
          signed.to_json(syntax: :general).should == {
            payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
            signatures: [{
              protected: Base64.urlsafe_encode64(signed.header.to_json, padding: false),
              signature: Base64.urlsafe_encode64(signed.signature, padding: false)
            }]
          }.to_json
        end
        context 'with blank payload' do
          it 'should return General JWS JSON Serialization' do
            signed_blank.to_json(syntax: :general).should == {
              payload: '',
              signatures: [{
                protected: Base64.urlsafe_encode64(signed_blank.header.to_json, padding: false),
                signature: Base64.urlsafe_encode64(signed_blank.signature, padding: false)
              }]
            }.to_json
          end
        end

        context 'when not signed yet' do
          it 'should not fail' do
            jws.to_json(syntax: :general).should == {
              payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
              signatures: [{
                protected: Base64.urlsafe_encode64(jws.header.to_json, padding: false),
                signature: Base64.urlsafe_encode64('', padding: false)
              }]
            }.to_json
          end
          context 'with blank payload' do
            it 'should not fail' do
              jws_blank.to_json(syntax: :general).should == {
                payload: '',
                signatures: [{
                  protected: Base64.urlsafe_encode64(jws_blank.header.to_json, padding: false),
                  signature: Base64.urlsafe_encode64('', padding: false)
                }]
              }.to_json
            end
          end
        end
      end

      context 'when flattened' do
        it 'should return Flattened JWS JSON Serialization' do
          signed.to_json(syntax: :flattened).should == {
            protected: Base64.urlsafe_encode64(signed.header.to_json, padding: false),
            payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
            signature: Base64.urlsafe_encode64(signed.signature, padding: false)
          }.to_json
        end
        context 'with blank payload' do
          it 'should return Flattened JWS JSON Serialization' do
            signed_blank.to_json(syntax: :flattened).should == {
              protected: Base64.urlsafe_encode64(signed_blank.header.to_json, padding: false),
              payload: '',
              signature: Base64.urlsafe_encode64(signed_blank.signature, padding: false)
            }.to_json
          end
        end

        context 'when not signed yet' do
          it 'should not fail' do
            jws.to_json(syntax: :flattened).should == {
              protected: Base64.urlsafe_encode64(jws.header.to_json, padding: false),
              payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
              signature: Base64.urlsafe_encode64('', padding: false)
            }.to_json
          end
          context 'with blank payload' do
            it 'should not fail' do
              jws_blank.to_json(syntax: :flattened).should == {
                protected: Base64.urlsafe_encode64(jws_blank.header.to_json, padding: false),
                payload: '',
                signature: Base64.urlsafe_encode64('', padding: false)
              }.to_json
            end
          end
        end
      end
    end
  end
end
