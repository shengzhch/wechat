package account_manage

//微信带参数的二维码信息
type QrcodeInfo struct {
	Expire_seconds int    `json:"expire_seconds,omitempty"`
	Action_name    string `json:"action_name"`
	Action_info struct {
		Scene struct {
			Scene_id  int32  `json:"scene_id,omitempty"`
			Scene_str string `json:"scene_str,omitempty"`
		} `json:"scene"`
	} `json:"action_info"`
}

func CreateQrcode(token string, qi *QrcodeInfo, wanted interface{}) (err error) {
	return nil
}
