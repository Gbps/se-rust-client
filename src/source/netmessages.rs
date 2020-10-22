use crate::protoutil;
use crate::source::bitbuf::{WireWriter};
use bitstream_io::{BitWriter, LittleEndian};
use smallvec::{SmallVec};
use crate::source::protos::*;
use ::protobuf::ProtobufEnum;
use NET_Messages::*;
use SVC_Messages::*;

type ProtoMessage = Box<dyn ::protobuf::Message>;

// a netmessage packet, either to be sent or received from the network
pub struct NetMessage
{
    // the netmessage enum identifier for this message
    id: i32,

    // the size of this encoded message
    size: u32,

    // the internal protobuf message for this netmessage
    message: ProtoMessage,
}

impl NetMessage
{
    // Decode a netmessage into a NetMessage object
    pub fn bind(id: i32, buffer: &[u8]) -> anyhow::Result<NetMessage>
    {
        let net_enum = NET_Messages::from_i32(id as i32);
        if net_enum.is_some()
        {
            return match net_enum.unwrap()
            {
                net_NOP => Self::from_buffer::<CNETMsg_NOP>(buffer, id),
                net_Disconnect => Self::from_buffer::<CNETMsg_Disconnect>(buffer, id),
                net_File => Self::from_buffer::<CNETMsg_File>(buffer, id),
                net_SplitScreenUser => Self::from_buffer::<CNETMsg_SplitScreenUser>(buffer, id),
                net_Tick => Self::from_buffer::<CNETMsg_Tick>(buffer, id),
                net_StringCmd => Self::from_buffer::<CNETMsg_StringCmd>(buffer, id),
                net_SetConVar => Self::from_buffer::<CNETMsg_SetConVar>(buffer, id),
                net_SignonState => Self::from_buffer::<CNETMsg_SignonState>(buffer, id),
                net_PlayerAvatarData => Self::from_buffer::<CNETMsg_PlayerAvatarData>(buffer, id),
            }
        }

        let svc_enum = SVC_Messages::from_i32(id as i32);
        if svc_enum.is_some()
        {
            return match svc_enum.unwrap()
            {
                svc_ServerInfo => Self::from_buffer::<CSVCMsg_ServerInfo>(buffer, id), 		// first message from server about game; map etc
                svc_SendTable => Self::from_buffer::<CSVCMsg_SendTable>(buffer, id),		// sends a sendtable description for a game class
                svc_ClassInfo => Self::from_buffer::<CSVCMsg_ClassInfo>(buffer, id),		// Info about classes (first byte is a CLASSINFO_ define).
                svc_SetPause => Self::from_buffer::<CSVCMsg_SetPause>(buffer, id),		// tells client if server paused or unpaused
                svc_CreateStringTable => Self::from_buffer::<CSVCMsg_CreateStringTable>(buffer, id),		// inits shared string tables
                svc_UpdateStringTable => Self::from_buffer::<CSVCMsg_UpdateStringTable>(buffer, id),		// updates a string table
                svc_VoiceInit => Self::from_buffer::<CSVCMsg_VoiceInit>(buffer, id),		// inits used voice codecs & quality
                svc_VoiceData => Self::from_buffer::<CSVCMsg_VoiceData>(buffer, id),		// Voicestream data from the server
                svc_Print => Self::from_buffer::<CSVCMsg_Print>(buffer, id),		// print text to console
                svc_Sounds => Self::from_buffer::<CSVCMsg_Sounds>(buffer, id),		// starts playing sound
                svc_SetView => Self::from_buffer::<CSVCMsg_SetView>(buffer, id),		// sets entity as point of view
                svc_FixAngle => Self::from_buffer::<CSVCMsg_FixAngle>(buffer, id),		// sets/corrects players viewangle
                svc_CrosshairAngle => Self::from_buffer::<CSVCMsg_CrosshairAngle>(buffer, id),		// adjusts crosshair in auto aim mode to lock on traget
                svc_BSPDecal => Self::from_buffer::<CSVCMsg_BSPDecal>(buffer, id),		// add a static decal to the world BSP
                svc_SplitScreen => Self::from_buffer::<CSVCMsg_SplitScreen>(buffer, id),		// split screen style message
                svc_UserMessage => Self::from_buffer::<CSVCMsg_UserMessage>(buffer, id),		// a game specific message
                svc_EntityMessage => Self::from_buffer::<CSVCMsg_EntityMsg>(buffer, id),		// a message for an entity
                svc_GameEvent => Self::from_buffer::<CSVCMsg_GameEvent>(buffer, id),		// global game event fired
                svc_PacketEntities => Self::from_buffer::<CSVCMsg_PacketEntities>(buffer, id),		// non-delta compressed entities
                svc_TempEntities => Self::from_buffer::<CSVCMsg_TempEntities>(buffer, id),		// non-reliable event object
                svc_Prefetch => Self::from_buffer::<CSVCMsg_Prefetch>(buffer, id),		// only sound indices for now
                svc_Menu => Self::from_buffer::<CSVCMsg_Menu>(buffer, id),		// display a menu from a plugin
                svc_GameEventList => Self::from_buffer::<CSVCMsg_GameEventList>(buffer, id),		// list of known games events and fields
                svc_GetCvarValue => Self::from_buffer::<CSVCMsg_GetCvarValue>(buffer, id),		// Server wants to know the value of a cvar on the client
                svc_PaintmapData => Self::from_buffer::<CSVCMsg_PaintmapData>(buffer, id),
                svc_CmdKeyValues => Self::from_buffer::<CSVCMsg_CmdKeyValues>(buffer, id),		// Server submits KeyValues command for the client
                svc_EncryptedData => Self::from_buffer::<CSVCMsg_EncryptedData>(buffer, id),
                svc_HltvReplay => Self::from_buffer::<CSVCMsg_HltvReplay>(buffer, id),
                svc_Broadcast_Command  => Self::from_buffer::<CSVCMsg_Broadcast_Command>(buffer, id),
            }
        }

        Err(anyhow::anyhow!("Unknown netmessage id {}!", id))
    }

    // get the inner proto message
    pub fn inner(&self) -> &ProtoMessage
    {
        return &self.message;
    }

    // get the maximum size of the encoded message with the header
    pub fn get_max_size(&self) -> usize
    {
        return (self.size + 8) as usize;
    }

    // write the netmessage (with header) to a vector, clears the vector beforehand
    pub fn encode_to_buffer(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()>
    {
        // TODO: Encode message directly to buf

        // create a stack/heap allocated buffer hopefully to optimize small netmessage encodings
        let mut encode_buf: SmallVec<[u8; 2048]> = SmallVec::with_capacity(self.size as usize);

        let cursor = std::io::Cursor::new(buf);
        let mut writer = BitWriter::endian(cursor, LittleEndian);

        // encode the proto message
        self.message.write_to_writer(&mut encode_buf)?;

        // write the netmessage header and proto message
        writer.write_int32_var(self.id as u32)?;
        writer.write_int32_var(self.size)?;
        writer.write_bytes(&encode_buf)?;

        Ok(())
    }

    // create a message to send from a proto message and the id of the message
    pub fn from_proto(message: ProtoMessage, id: i32) -> Self {
        NetMessage{
            id,
            size: message.compute_size(),
            message,
        }
    }

    // create a message from a network buffer
    pub fn from_buffer<M>(message: &[u8], id: i32) -> anyhow::Result<Self>
        where M: ::protobuf::Message
    {
        let msg: ProtoMessage = Box::new(protoutil::deserialize::<M>(message)?);

        Ok(NetMessage{
            id,
            size: msg.get_cached_size(),
            message: msg,
        })
    }

    // get the type name of this netmessage
    pub fn get_type_name(&self) -> &'static str
    {
        let net_enum = NET_Messages::from_i32(self.id);
        if net_enum.is_some()
        {
            return net_enum.unwrap().descriptor().name();
        }

        let svc_enum = SVC_Messages::from_i32(self.id);
        if svc_enum.is_some()
        {
            return svc_enum.unwrap().descriptor().name();
        }

        return "<Unknown Netmessage Id>";
    }
}
