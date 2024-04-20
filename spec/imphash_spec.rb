require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "PEdump" do
  describe "#imphash" do
    {
      'OmniPrintAdjuster2X.asp2.ocx'   => '1bd49b5ac5dc30f99979bf868dd3a61d',
      'OmniPrintAdjuster2X.ocx'        => '3c02ed1c2f313e0b8f96227aff0e6b2b',
      'arm_upx.exe'                    => '3a36a12249db6681f7a2c815494924ff',
      'bad_imports.exe'                => nil,
      'calc.asp212.exe'                => '83021ae7183fb69910509cf77a9616a4',
      'calc.exe'                       => '15424d7bd976766dc8b2452077f79c09',
      'calc_upx.exe'                   => 'a233151640d5ba9243a4e28da9662fd5',
      'notepad.asp212.exe'             => '179e6499a029c1233b97e654ab2b6d6d',
      'notepad.asp22.exe'              => '179e6499a029c1233b97e654ab2b6d6d',
      'notepad.asp228.exe'             => '179e6499a029c1233b97e654ab2b6d6d',
      'notepad.exe'                    => '419c3fe8c1eefea9336b96f74f0951dd',
      'tasklist.asp212.exe'            => '615b08b04525e03e96d2c2f889b016ee',
      'tasklist.exe'                   => 'fb207d3860c1e608ed020ccb4a9f9aef',
      'upx.exe'                        => 'a75d408dd51ece143f6aacfda06a28da',
      'zlib.dll'                       => '3a57cfcb7f0a7b02e430b0c1143f4b28'
    }.each do |fname, expected_hash|
      it "should return correct imphash for #{fname}" do
        PEdump.dump("samples/#{fname}", log_level: Logger::FATAL).imphash.should == expected_hash
      end
    end
  end
end
