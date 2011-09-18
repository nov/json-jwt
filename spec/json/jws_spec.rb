require 'spec_helper'

describe JSON::JWS do
  let(:jwt) { JSON::JWT.new claims }
  let(:jws) { JSON::JWS.new jwt }
  let(:claims) do
    {
      :iss => 'joe',
      :exp => 1300819380,
      'http://example.com/is_root' => true
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

  describe '#sign' do
    shared_examples_for :jwt_with_expected_signature do
      it 'should generate expected signature' do
        UrlSafeBase64.encode64(signed.signature).should == expected_signature[alg]
      end
    end
    let(:expected_signature) {
      {
        :HS256 => 'DyuTgO2Ggb5nrhkkhI-RjVYIBe3o8oL4ijkAn94YPxQ',
        :HS384 => 'a5-7rr61TG8Snv9xxJ7l064ky-SCq1Mswe9t8HEorvoc_nnfIeUy9WQCLMIli34R',
        :HS512 => 'ce-GlHDaNwaHfmAFRGp3QPPKvrpruTug2hC1bf6yNlbuvkMwJw2jFZgq_4wmIPetRdiBy7XFq7rrtmw1Im7tmQ',
        :RS256 => 'E5VELqAdla2Bx1axc9KFxO0EiCr0Mw6HPYX070qGQ8zA_XmyxGPUZLyyWU_6Cn399W-oYBWO2ynLlr8pqqjP3jXevyCeYeGRVN0HzLYiBebEugNnc3hevr7WV2UzfksWRA-Ux2bDv2sz9p_LGbL33wWNxGDvIlpDyZUul_a48nCipS0riBjkTLTSE8dfBxQTXEF5GEUUu99ot6aBLzUhc25nHXSXogXF6MHK-hAcE7f4v-vJ0lbPbHLVGUopIoxoqe4XjoBpzE5UvhrVl5LYbdjbyJhu5ZIA8GLsgwtUFh3dfdIechORoR3k5NSFSv8157bAEa8t4iwgWD2MSNSQnw',
        :RS384 => 'lT5JbytGKgG9QrwkJuxgw7UjmN9tjkEQW9pVGR2XnKEdC0_wLNIzAmT-jTwyMDGBLUkWO7opDOP6Xy6_DOTg58k9PwVkyQzrLnmxJMEng2Q-aMqcitRSIvUk3DPy8kemp8yUPls9NzWmByM2GoUVHbDsR0r-tZN-g_9QYev32mvMhjMr30JI5S2xiRjc9m2GAaXMOQmNTovJgV4bgCp4UjruCrA0BD1JJwDqKYoR_YYr_ALcVjD_LUgy80udJvbi8MAYJVUf0QYtQDrX2wnT_-eiiWjD5XafLuXEQVDRh-v2MKAwdvtXMq5cZ08Zjl2SyHxJ3OqhEeWPvYGltxZh_A',
        :RS512 => 'EHeGM2Mo3ghhUfSB99AlREehrbC6OPE-nYL_rwf88ysTnJ8L1QQ0UuCrXq4SpRutGLK_bYTK3ZALvFRPoOgK_g0QWmqv6qjQRU_QTxoq8y8APP-IgKKDuIiGH6daBV2rAPLDReqYNKsKjmTvZJo2c0a0e_WZkkj_ZwpgjTG3v0gW9lbDAzLJDz18eqtR4ZO7JTu_fyNrUrNk-w2_wpxSsn9sygIMp0lKE0_pt0b01fz3gjTDjlltU0cKSalUp4geaBDH7QRcexrolIctdQFbNKTXQxoigxD3NLNkKGH7f6A8KZdcOm8AnEjullcZs8_OWGnW43p1qrxoBRSivb9pqQ',
        :ES256 => :TODO,
        :ES384 => :TODO,
        :ES512 => :TODO
      }
    }
    let(:signed) do
      jws.sign key, alg
    end
    subject { signed }
    
    [:HS256, :HS384, :HS512].each do |algorithm|
      describe algorithm do
        let(:key) { shared_secret }
        let(:alg) { algorithm }
        it_behaves_like :jwt_with_alg
        it_behaves_like :jwt_with_expected_signature
      end
    end

    [:RS256, :RS384, :RS512].each do |algorithm|
      describe algorithm do
        let(:key) { private_key }
        let(:alg) { algorithm }
        it_behaves_like :jwt_with_alg
        it_behaves_like :jwt_with_expected_signature
      end
    end

    [:ES256, :ES384, :ES512].each do |algorithm|
      describe algorithm do
        let(:alg) { algorithm }
        it :TODO
      end
    end
  end
end